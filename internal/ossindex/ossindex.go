package ossindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/nscuro/gotalias/internal/graphdb"
)

const (
	source = "OSSINDEX"
)

func Mirror(logger zerolog.Logger, db *graphdb.DB, username, token string, purls []string) error {
	logger = logger.With().Str("source", source).Logger()

	chunks := chunkCoordinates(purls)
	logger.Info().Msgf("divided %d purls into %d chunks", len(purls), len(chunks))

	for i, chunk := range chunkCoordinates(purls) {
		logger.Info().Msgf("fetching reports for chunk %d/%d", i+1, len(chunks))
		reports, err := getComponentReports(username, token, chunk)
		if err != nil {
			return fmt.Errorf("failed to get component reports: %w", err)
		}

		for _, report := range reports {
			for _, vuln := range report.Vulnerabilities {
				err = insertVulnerability(db, vuln)
				if err != nil {
					return fmt.Errorf("failed to insert vulnerability: %w", err)
				}
			}
		}
	}

	return nil
}

func insertVulnerability(db *graphdb.DB, vuln vulnerability) error {
	err := db.AddVulnerability(vuln.ID)
	if err != nil {
		return fmt.Errorf("failed to add vulnerability %s: %w", vuln.ID, err)
	}

	if vuln.CVE != "" && vuln.ID != vuln.CVE {
		err = db.AddVulnerability(vuln.CVE)
		if err != nil {
			return fmt.Errorf("failed to add vulnerability %s as alias for %s: %w", vuln.CVE, vuln.ID, err)
		}

		err = db.AddAlias(vuln.ID, vuln.CVE, source)
		if err != nil {
			return fmt.Errorf("failed to add alias relationship %s -> %s: %w", vuln.CVE, vuln.ID, err)
		}
		err = db.AddAlias(vuln.CVE, vuln.ID, source)
		if err != nil {
			return fmt.Errorf("failed to add alias relationship %s -> %s: %w", vuln.ID, vuln.CVE, err)
		}
	}

	return nil
}

type componentReport struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type componentReportsRequest struct {
	Coordinates []string `json:"coordinates"`
}

type vulnerability struct {
	ID  string `json:"id"`
	CVE string `json:"cve"`
}

func getComponentReports(username, token string, coordinates []string) ([]componentReport, error) {
	buf := bytes.Buffer{}
	err := json.NewEncoder(&buf).Encode(componentReportsRequest{
		Coordinates: coordinates,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://ossindex.sonatype.org/api/v3/component-report", &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}

	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/vnd.ossindex.component-report.v1+json")
	req.Header.Set("Content-Type", "application/vnd.ossindex.component-report-request.v1+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %d", res.StatusCode)
	}

	var reports []componentReport
	err = json.NewDecoder(res.Body).Decode(&reports)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return reports, nil
}

func chunkCoordinates(coordinates []string) [][]string {
	var chunks [][]string

	for i := 0; i < len(coordinates); i += 128 {
		j := i + 128

		if j > len(coordinates) {
			j = len(coordinates)
		}

		chunks = append(chunks, coordinates[i:j])
	}

	return chunks
}
