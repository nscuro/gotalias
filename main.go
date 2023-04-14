package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strings"
	"sync"

	"github.com/nscuro/gotalias/internal/github"

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
		mirrorOSV     bool
		githubToken   string
		ossIndexUser  string
		ossIndexToken string
		snykOrgId     string
		snykTokens    string
		purlsFile     string
	)
	flag.BoolVar(&mirrorOSV, "osv", false, "Mirror OSV")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
	flag.StringVar(&ossIndexUser, "ossindex-user", "", "OSS Index username")
	flag.StringVar(&ossIndexToken, "ossindex-token", "", "OSS Index token")
	flag.StringVar(&snykOrgId, "snyk-orgid", "", "Snyk org ID")
	flag.StringVar(&snykTokens, "snyk-tokens", "", "Snyk token")
	flag.StringVar(&purlsFile, "purls", "", "Path to PURLs file")
	flag.Parse()

	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})

	neoCtx := context.TODO()
	driver, err := neo4j.NewDriverWithContext("neo4j://localhost:7687", neo4j.NoAuth())
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize driver")
	}
	defer driver.Close(neoCtx)

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
		session := driver.NewSession(neoCtx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeWrite,
		})
		defer session.Close(neoCtx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msg("mirroring osv")
			err = osv.Mirror(logger, graphdb.New(session))
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror osv")
			}
		}()
	}

	if githubToken != "" {
		session := driver.NewSession(neoCtx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeWrite,
		})
		defer session.Close(neoCtx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msg("mirroring github")
			err = github.Mirror(logger, graphdb.New(session), githubToken)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror github")
			}
		}()
	}

	if ossIndexUser != "" && ossIndexToken != "" {
		session := driver.NewSession(neoCtx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeWrite,
		})
		defer session.Close(neoCtx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msgf("mirroring oss index data for %d purls", len(purls))
			err = ossindex.Mirror(logger, graphdb.New(session), ossIndexUser, ossIndexToken, purls)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror ossindex")
			}
		}()
	}

	if snykOrgId != "" && snykTokens != "" {
		session := driver.NewSession(neoCtx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeWrite,
		})
		defer session.Close(neoCtx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msgf("mirroring snyk data for %d purls", len(purls))
			err = snyk.Mirror(logger, graphdb.New(session), snykOrgId, strings.Split(snykTokens, ","), purls)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror snyk")
			}
		}()
	}

	wg.Wait()
}
