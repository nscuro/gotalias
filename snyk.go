package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const snykBaseURL = "https://api.snyk.io"

var snykLimiter = rate.NewLimiter(rate.Every(time.Minute/100), 100)

func MirrorSnyk(ns neo4j.SessionWithContext, orgId, token string, purls []string) error {
	for _, purl := range purls {
		issues, err := getSnykIssues(orgId, token, purl)
		if err != nil {
			return err
		}

		for _, issue := range issues {
			err = insertIssue(ns, issue)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func insertIssue(ns neo4j.SessionWithContext, issue snykIssue) error {
	tx, err := ns.BeginTransaction(context.TODO())
	if err != nil {
		return err
	}

	// Ensure vulnerability exists
	_, err = tx.Run(context.TODO(), `MERGE (:Vulnerability {id: $id})`, map[string]any{"id": issue.Key})
	if err != nil {
		return err
	}

	for _, problem := range issue.Problems {
		if problem.Source != "GHSA" && problem.Source != "CVE" {
			log.Printf("skipping problem source %s", problem.Source)
			continue
		}

		// Ensure the aliased vulnerability exists
		_, err = tx.Run(context.TODO(), `MERGE (:Vulnerability {id: $id})`, map[string]any{"id": problem.ID})
		if err != nil {
			return err
		}

		// Create a bidirectional relationship between vulnerability and alias
		_, err = tx.Run(context.TODO(), `
MATCH (a:Vulnerability {id:$id}), (b:Vulnerability{id:$alias}) 
MERGE (a)-[:ALIASES {reportedBy:["SNYK"]}]->(b)-[:ALIASES {reportedBy:["SNYK"]}]->(a)`, map[string]any{"id": issue.Key, "alias": problem.ID})
		if err != nil {
			return err
		}
	}

	return tx.Commit(context.TODO())
}

func getSnykIssues(orgId, token, purl string) ([]snykIssue, error) {
	err := snykLimiter.Wait(context.TODO())
	if err != nil {
		return nil, err
	}

	purl = strings.Split(purl, "?")[0]
	purl = url.QueryEscape(purl)

	reqURL, err := url.JoinPath(snykBaseURL, "rest", "orgs", orgId, "packages", purl, "issues")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("version", "2022-11-14")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "token "+token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusTooManyRequests {
		panic("ratelimit")
	} else if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code for request %s: %d", reqURL, res.StatusCode)
	}

	var sr snykResponse
	err = json.NewDecoder(res.Body).Decode(&sr)
	if err != nil {
		return nil, err
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
