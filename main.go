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
		mirrorOSV      bool
		mirrorGitHub   bool
		githubToken    string
		mirrorOSSIndex bool
		ossIndexUser   string
		ossIndexToken  string
		mirrorSnyk     bool
		snykOrgId      string
		snykToken      string
		purlsFile      string
	)
	flag.BoolVar(&mirrorOSV, "osv", false, "Mirror OSV")
	flag.BoolVar(&mirrorGitHub, "github", false, "Mirror GitHub")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
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

	if mirrorGitHub {
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

	if mirrorOSSIndex {
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

	if mirrorSnyk {
		session := driver.NewSession(neoCtx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeWrite,
		})
		defer session.Close(neoCtx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info().Msgf("mirroring snyk data for %d purls", len(purls))
			err = snyk.Mirror(logger, graphdb.New(session), snykOrgId, snykToken, purls)
			if err != nil {
				logger.Fatal().Err(err).Msg("failed to mirror snyk")
			}
		}()
	}

	wg.Wait()
}
