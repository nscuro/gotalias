package osv

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/vuln/osv"

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
		if strings.Contains(ecosystem, ":") {
			logger.Info().Str("ecosystem", ecosystem).Msg("skipping sub-ecosystem")
			continue
		}

		logger.Info().Str("ecosystem", ecosystem).Msg("mirroring ecosystem")
		entryChan, errChan := downloadEcosystem(ctx, ecosystem)
	loop:
		for {
			select {
			case entry, open := <-entryChan:
				if !open {
					logger.Info().Str("ecosystem", ecosystem).Msg("no more entries")
					break loop
				}
				err := insertEntry(db, entry)
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

func insertEntry(db *graphdb.DB, entry osv.Entry) error {
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

	return nil
}

func downloadEcosystem(ctx context.Context, ecosystem string) (<-chan osv.Entry, <-chan error) {
	entryChan := make(chan osv.Entry, 1)
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
				log.Println(ctx.Err())
				return
			default:
			}

			file, err := zipFile.Open()
			if err != nil {
				errChan <- err
				continue
			}

			var entry osv.Entry
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
