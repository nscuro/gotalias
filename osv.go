package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/vuln/osv"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const osvBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

func MirrorOSV(ns neo4j.SessionWithContext) error {
	ecosystems, err := GetEcosystems()
	if err != nil {
		return err
	}

	for _, ecosystem := range ecosystems {
		if strings.Contains(ecosystem, ":") {
			log.Printf("skipping sub-ecosystem %s", ecosystem)
			continue
		}

		log.Printf("processing ecosystem %s...", ecosystem)
		err = InsertEcosystem(ns, ecosystem)
		if err != nil {
			return err
		}

		entryChan, errChan := DownloadEcosystem(ecosystem)

	loop:
		for {
			select {
			case entry, open := <-entryChan:
				if !open {
					log.Printf("no more entries for ecosystem %s", ecosystem)
					break loop
				}
				err := InsertEntry(ns, ecosystem, entry)
				if err != nil {
					log.Printf("failed to insert entry %s: %v", entry.ID, err)
				}
			case err := <-errChan:
				fmt.Printf("got error: %v", err)
			}
		}
	}

	return nil
}

func InsertEcosystem(ns neo4j.SessionWithContext, ecosystem string) error {
	tx, err := ns.BeginTransaction(context.TODO())
	if err != nil {
		return err
	}

	_, err = tx.Run(context.TODO(), `MERGE (:Ecosystem {name: $name})`, map[string]any{"name": ecosystem})
	if err != nil {
		return err
	}

	return tx.Commit(context.TODO())
}

func InsertEntry(ns neo4j.SessionWithContext, ecosystem string, entry osv.Entry) error {
	tx, err := ns.BeginTransaction(context.TODO())
	if err != nil {
		return err
	}

	// Ensure vulnerability exists
	_, err = tx.Run(context.TODO(), `MERGE (:Vulnerability {id: $id})`, map[string]any{"id": entry.ID})
	if err != nil {
		return err
	}

	_, err = tx.Run(context.TODO(), `MATCH (e:Ecosystem {name: $ecosystem}), (v:Vulnerability {id: $id}) MERGE (e)-[:CONTAINS]->(v)`, map[string]any{"ecosystem": ecosystem, "id": entry.ID})
	if err != nil {
		return err
	}

	for _, alias := range entry.Aliases {
		// Ensure the aliased vulnerability exists
		_, err = tx.Run(context.TODO(), `MERGE (:Vulnerability {id: $id})`, map[string]any{"id": alias})
		if err != nil {
			return err
		}

		// Create a bidirectional relationship between vulnerability and alias
		_, err = tx.Run(context.TODO(), `
MATCH (a:Vulnerability {id:$id}), (b:Vulnerability{id:$alias}) 
MERGE (a)-[:ALIASES {reportedBy:["OSV"]}]->(b)-[:ALIASES {reportedBy:["OSV"]}]->(a)`, map[string]any{"id": entry.ID, "alias": alias})
		if err != nil {
			return err
		}
	}

	return tx.Commit(context.TODO())
}

func DownloadEcosystem(ecosystem string) (<-chan osv.Entry, <-chan error) {
	entryChan := make(chan osv.Entry, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			close(entryChan)
			close(errChan)
		}()

		fileURL, err := url.JoinPath(osvBaseURL, ecosystem, "all.zip")
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

func GetEcosystems() ([]string, error) {
	ecosystemsURL, err := url.JoinPath(osvBaseURL, "ecosystems.txt")
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
