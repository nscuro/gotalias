package main

import (
	"bufio"
	"context"
	"flag"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
	"os"
	"strings"
)

func main() {
	var (
		dbUser     string
		dbPass     string
		mirrorOSV  bool
		mirrorSnyk bool
		snykOrgId  string
		snykToken  string
		purlsFile  string
	)
	flag.StringVar(&dbUser, "db-user", "neo4j", "Database username")
	flag.StringVar(&dbPass, "db-pass", "", "Database password")
	flag.BoolVar(&mirrorOSV, "osv", false, "Mirror OSV")
	flag.BoolVar(&mirrorSnyk, "snyk", false, "Mirror snyk")
	flag.StringVar(&snykOrgId, "snyk-orgid", "", "Snyk org ID")
	flag.StringVar(&snykToken, "snyk-token", "", "Snyk token")
	flag.StringVar(&purlsFile, "purls", "", "Path to PURLs file")
	flag.Parse()

	ctx := context.TODO()

	driver, err := neo4j.NewDriverWithContext("neo4j://localhost:7687", neo4j.BasicAuth(dbUser, dbPass, ""))
	if err != nil {
		log.Fatalf("failed to initialize driver: %v", err)
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer session.Close(ctx)

	purls := make([]string, 0)
	if purlsFile != "" {
		log.Printf("reading purls from %s", purlsFile)

		pf, err := os.Open(purlsFile)
		if err != nil {
			log.Fatalf("failed to open purls file: %v", err)
		}

		scanner := bufio.NewScanner(pf)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text != "" {
				purls = append(purls, text)
			}
		}

		pf.Close()
	}

	if mirrorOSV {
		log.Println("mirroring osv")
		err = MirrorOSV(session)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if mirrorSnyk {
		log.Printf("mirroring snyk data for %d purls", len(purls))
		err = MirrorSnyk(session, snykOrgId, snykToken, purls)
		if err != nil {
			log.Fatalln(err)
		}
	}
}
