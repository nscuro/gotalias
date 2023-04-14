package snyk

import (
	"container/ring"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/nscuro/gotalias/internal/graphdb"
)

const (
	baseURL = "https://api.snyk.io"
	source  = "SNYK"
)

func Mirror(logger zerolog.Logger, db *graphdb.DB, orgId string, tokens []string, purls []string) error {
	logger = logger.With().Str("source", source).Logger()

	tokenRing := ring.New(len(tokens))
	for i := 0; i < tokenRing.Len(); i++ {
		tokenRing.Value = tokens[i]
		tokenRing = tokenRing.Next()
	}

	for _, purl := range purls {
		if !isSupported(purl) {
			logger.Warn().Str("purl", purl).Msg("skipping unsupported purl")
			continue
		}

		issues, err := getSnykIssues(orgId, tokenRing.Next().Value.(string), purl)
		if err != nil {
			logger.Warn().Str("purl", purl).Err(err).Msg("failed get issues")
			continue
		}

		for _, issue := range issues {
			err = insertIssue(logger, db, issue)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func insertIssue(logger zerolog.Logger, db *graphdb.DB, issue snykIssue) error {
	err := db.AddVulnerability(issue.Key)
	if err != nil {
		return fmt.Errorf("failed to add vulnerability %s: %w", issue.Key, err)
	}

	for _, problem := range issue.Problems {
		if problem.Source == "CWE" {
			err = db.AddCWE(issue.Key, problem.ID, source)
			if err != nil {
				return fmt.Errorf("failed to add cwe for vulnerability %s: %w", issue.Key, err)
			}
		}

		if problem.Source == "GHSA" || problem.Source == "CVE" {
			err = db.AddVulnerability(problem.ID)
			if err != nil {
				return fmt.Errorf("failed to add vulnerability %s as alias for %s: %w", problem.ID, issue.Key, err)
			}

			err = db.AddAlias(issue.Key, problem.ID, source)
			if err != nil {
				return fmt.Errorf("failed to add alias relationship %s -> %s: %w", problem.ID, issue.Key, err)
			}
			err = db.AddAlias(problem.ID, issue.Key, source)
			if err != nil {
				return fmt.Errorf("failed to add alias relationship %s -> %s: %w", issue.Key, problem.ID, err)
			}
		}
	}

	for _, severity := range issue.Severities {
		err = db.AddCVSS(issue.Key, severity.Score, severity.Vector, fmt.Sprintf("%s/%s", source, severity.Source))
		if err != nil {
			return fmt.Errorf("failed to add cvss details for vulnerability %s: %w", issue.Key, err)
		}
	}

	return nil
}

func getSnykIssues(orgId, token, purl string) ([]snykIssue, error) {
	purl = strings.Split(purl, "?")[0]
	purl = url.QueryEscape(purl)

	reqURL, err := url.JoinPath(baseURL, "rest", "orgs", orgId, "packages", purl, "issues")
	if err != nil {
		return nil, fmt.Errorf("failed to construct request url: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}

	q := req.URL.Query()
	q.Set("version", "2022-11-14")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "token "+token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusTooManyRequests {

	} else if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code for request %s: %d", reqURL, res.StatusCode)
	}

	var sr snykResponse
	err = json.NewDecoder(res.Body).Decode(&sr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	issues := make([]snykIssue, 0)
	for _, data := range sr.Data {
		issues = append(issues, data.Attributes)
	}

	return issues, nil
}

var supportedPURLTypes = []string{
	"cargo",
	"cocoapods",
	"composer",
	"gem",
	"generic",
	"hex",
	"maven",
	"npm",
	"nuget",
	"pypi",
}

func isSupported(purl string) bool {
	for _, purlType := range supportedPURLTypes {
		if strings.HasPrefix(strings.ToLower(purl), fmt.Sprintf("pkg:%s", purlType)) {
			return true
		}
	}

	return false
}

type snykResponse struct {
	Data []snykResponseData `json:"data"`
}

type snykResponseData struct {
	Attributes snykIssue `json:"attributes"`
}

type snykIssue struct {
	Key        string         `json:"key"`
	CreatedAt  string         `json:"created_at"`
	UpdatedAt  string         `json:"updated_at"`
	Problems   []snykProblem  `json:"problems"`
	Severities []snykSeverity `json:"severities"`
}

type snykProblem struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

type snykSeverity struct {
	Level  string  `json:"level"`
	Score  float64 `json:"score"`
	Source string  `json:"source"`
	Vector string  `json:"vector"`
}
