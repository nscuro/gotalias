package osv

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	cvssv2 "github.com/goark/go-cvss/v2"
	cvssv3 "github.com/goark/go-cvss/v3/metric"
	"github.com/rs/zerolog"

	"github.com/nscuro/gotalias/internal/graphdb"
)

const (
	baseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	source  = "OSV"
)

func Mirror(logger zerolog.Logger, db *graphdb.DB) error {
	logger = logger.With().Str("source", source).Logger()

	ecosystems, err := getEcosystems()
	if err != nil {
		return fmt.Errorf("failed to fetch ecosystem list: %w", err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	for _, ecosystem := range ecosystems {
		if strings.Contains(ecosystem, ":") || strings.HasPrefix(ecosystem, "Debian") {
			logger.Info().Str("ecosystem", ecosystem).Msg("skipping sub-ecosystem")
			continue
		}

		logger.Info().Str("ecosystem", ecosystem).Msg("mirroring ecosystem")
		entryChan, errChan := downloadEcosystem(ctx, logger, ecosystem)
	loop:
		for {
			select {
			case entry, open := <-entryChan:
				if !open {
					logger.Info().Str("ecosystem", ecosystem).Msg("no more entries")
					break loop
				}
				err := insertEntry(logger, db, entry)
				if err != nil {
					return fmt.Errorf("failed to insert entry %s: %w", entry.ID, err)
				}
			case err := <-errChan:
				logger.Warn().Err(err).Str("ecosystem", ecosystem).Msg("encountered error while downloading ecosystem")
			}
		}
	}

	return nil
}

func insertEntry(logger zerolog.Logger, db *graphdb.DB, entry osvEntry) error {
	err := db.AddVulnerability(entry.ID)
	if err != nil {
		return fmt.Errorf("failed to add vulnerability %s: %w", entry.ID, err)
	}

	for _, alias := range entry.Aliases {
		err = db.AddVulnerability(alias)
		if err != nil {
			return fmt.Errorf("failed to add vulnerability %s as alias for %s: %w", alias, entry.ID, err)
		}

		err = db.AddAlias(entry.ID, alias, source)
		if err != nil {
			return fmt.Errorf("failed to add alias relationship %s -> %s: %w", alias, entry.ID, err)
		}
		err = db.AddAlias(alias, entry.ID, source)
		if err != nil {
			return fmt.Errorf("failed to add alias relationship %s -> %s: %w", entry.ID, alias, err)
		}
	}

	for _, severity := range entry.Severity {
		var score float64
		if severity.Type == "CVSS_V2" {
			c := cvssv2.New()
			err = c.ImportBaseVector(severity.Score)
			if err != nil {
				logger.Warn().Err(err).Str("vector", severity.Score).Msg("failed to calculate cvssv2 score")
				continue
			}
			score = c.Base.Score()
		} else if severity.Type == "CVSS_V3" {
			base, err := cvssv3.NewBase().Decode(severity.Score)
			if err != nil {
				logger.Warn().Err(err).Str("vector", severity.Score).Msg("failed to calculate cvssv3 score")
				continue
			}
			score = base.Score()
		}

		err = db.AddCVSS(entry.ID, score, severity.Score, source)
		if err != nil {
			return fmt.Errorf("failed to add cvss details to vulnerability %s: %w", entry.ID, err)
		}
	}

	for _, cwe := range entry.DatabaseSpecific.CWEIDs {
		err = db.AddCWE(entry.ID, cwe, source)
		if err != nil {
			return fmt.Errorf("failed to add cwe for vulnerability %s: %w", entry.ID, err)
		}
	}

	return nil
}

type osvEntry struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

func downloadEcosystem(ctx context.Context, logger zerolog.Logger, ecosystem string) (<-chan osvEntry, <-chan error) {
	entryChan := make(chan osvEntry, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			close(entryChan)
			close(errChan)
		}()

		fileURL, err := url.JoinPath(baseURL, ecosystem, "all.zip")
		if err != nil {
			errChan <- err
			return
		}

		req, err := http.NewRequest(http.MethodGet, fileURL, nil)
		if err != nil {
			errChan <- err
			return
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		defer res.Body.Close()

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			errChan <- err
			return
		}

		zipReader, err := zip.NewReader(bytes.NewReader(resBody), int64(len(resBody)))
		if err != nil {
			errChan <- err
			return
		}

		for _, zipFile := range zipReader.File {
			select {
			case <-ctx.Done():
				logger.Warn().Err(err).Msg("aborted")
				return
			default:
			}

			file, err := zipFile.Open()
			if err != nil {
				errChan <- err
				continue
			}

			var entry osvEntry
			err = json.NewDecoder(file).Decode(&entry)
			if err != nil {
				errChan <- err
				file.Close()
				continue
			}

			entryChan <- entry
			file.Close()
		}
	}()

	return entryChan, nil
}

func getEcosystems() ([]string, error) {
	ecosystemsURL, err := url.JoinPath(baseURL, "ecosystems.txt")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, ecosystemsURL, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	ecosystems := make([]string, 0)
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		ecosystems = append(ecosystems, scanner.Text())
	}

	return ecosystems, nil
}
