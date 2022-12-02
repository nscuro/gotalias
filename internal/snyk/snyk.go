package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/nscuro/gotalias/internal/graphdb"
)

const (
	baseURL = "https://api.snyk.io"
	source  = "SNYK"
)

var limiter = rate.NewLimiter(rate.Every(time.Minute/100), 100)

func Mirror(logger zerolog.Logger, db *graphdb.DB, orgId, token string, purls []string) error {
	logger = logger.With().Str("source", source).Logger()

	for _, purl := range purls {
		issues, err := getSnykIssues(orgId, token, purl)
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
		if problem.Source != "GHSA" && problem.Source != "CVE" {
			logger.Info().Msgf("skipping problem source %s", problem.Source)
			continue
		}

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

	return nil
}

func getSnykIssues(orgId, token, purl string) ([]snykIssue, error) {
	err := limiter.Wait(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to wait for rate limiter: %w", err)
	}

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

type snykResponse struct {
	Data []snykResponseData `json:"data"`
}

type snykResponseData struct {
	Attributes snykIssue `json:"attributes"`
}

type snykIssue struct {
	Key      string        `json:"key"`
	Problems []snykProblem `json:"problems"`
}

type snykProblem struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}
