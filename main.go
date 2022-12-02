package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strings"
	"sync"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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

	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})

	neoCtx := context.TODO()
	driver, err := neo4j.NewDriverWithContext("neo4j://localhost:7687", neo4j.BasicAuth(dbUser, dbPass, ""))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize driver")
	}
	defer driver.Close(neoCtx)

	session := driver.NewSession(neoCtx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer session.Close(neoCtx)

	db := graphdb.New(session)

	purls := make([]string, 0)
	if purlsFile != "" {
		logger.Info().Msgf("reading purls from %s", purlsFile)

		pf, err := os.Open(purlsFile)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to open purls file")
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

	wg := sync.WaitGroup{}

	if mirrorOSV {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msg("mirroring osv")
			err = osv.Mirror(logger, db)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror osv")
			}
		}()
	}

	if mirrorOSSIndex {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msgf("mirroring oss index data for %d purls", len(purls))
			err = ossindex.Mirror(logger, db, ossIndexUser, ossIndexToken, purls)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror ossindex")
			}
		}()
	}

	if mirrorSnyk {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msgf("mirroring snyk data for %d purls", len(purls))
			err = snyk.Mirror(logger, db, snykOrgId, snykToken, purls)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror snyk")
			}
		}()
	}

	wg.Wait()
}
