package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/nscuro/gotalias/internal/graphdb"
	"github.com/nscuro/gotalias/internal/ossindex"
	"github.com/nscuro/gotalias/internal/osv"
	"github.com/nscuro/gotalias/internal/snyk"
)

func main() {
	var (
		dbUser         string
		dbPass         string
		mirrorOSV      bool
		mirrorOSSIndex bool
		ossIndexUser   string
		ossIndexToken  string
		mirrorSnyk     bool
		snykOrgId      string
		snykToken      string
		purlsFile      string
	)
	flag.StringVar(&dbUser, "db-user", "neo4j", "Database username")
	flag.StringVar(&dbPass, "db-pass", "", "Database password")
	flag.BoolVar(&mirrorOSV, "osv", false, "Mirror OSV")
	flag.BoolVar(&mirrorOSSIndex, "ossindex", false, "Mirror OSS Index")
	flag.StringVar(&ossIndexUser, "ossindex-user", "", "OSS Index username")
	flag.StringVar(&ossIndexToken, "ossindex-token", "", "OSS Index token")
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

	db := graphdb.New(session)

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
		err = osv.Mirror(db)
		if err != nil {
			log.Fatalf("failed to mirror osv: %v", err)
		}
	}

	if mirrorOSSIndex {
		log.Printf("mirroring oss index data for %d purls", len(purls))
		err = ossindex.Mirror(db, ossIndexUser, ossIndexToken, purls)
		if err != nil {
			log.Fatalf("failed to mirror ossindex: %v", err)
		}
	}

	if mirrorSnyk {
		log.Printf("mirroring snyk data for %d purls", len(purls))
		err = snyk.Mirror(db, snykOrgId, snykToken, purls)
		if err != nil {
			log.Fatalf("failed to mirror snyk: %v", err)
		}
	}
}
