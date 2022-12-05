package github

import (
	"context"
	"fmt"
	"github.com/nscuro/gotalias/internal/graphdb"
	"github.com/rs/zerolog"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const source = "GITHUB"

func Mirror(logger zerolog.Logger, db *graphdb.DB, token string) error {
	tokenSrc := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})
	httpClient := oauth2.NewClient(context.Background(), tokenSrc)
	client := githubv4.NewClient(httpClient)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	advisoryChan, errorChan := getAdvisories(ctx, logger, client)
loop:
	for {
		select {
		case advisory, open := <-advisoryChan:
			if !open {
				logger.Info().Msg("no more advisories")
				break loop
			}

			err := insertAdvisory(db, advisory)
			if err != nil {
				return fmt.Errorf("failed to insert advisory %s: %w", advisory.ID, err)
			}
		case err := <-errorChan:
			logger.Warn().Err(err).Msg("encountered error while fetching advisories")
		}
	}

	return nil
}

func insertAdvisory(db *graphdb.DB, advisory securityAdvisory) error {
	err := db.AddVulnerability(advisory.GhsaID)
	if err != nil {
		return fmt.Errorf("failed to add vulnerability %s: %w", advisory.GhsaID, err)
	}

	for _, identifier := range advisory.Identifiers {
		if identifier.Type == "CVE" {
			err = db.AddVulnerability(identifier.Value)
			if err != nil {
				return fmt.Errorf("failed to add vulnerability %s as alias for %s: %w", identifier.Value, advisory.GhsaID, err)
			}

			err = db.AddAlias(advisory.GhsaID, identifier.Value, source)
			if err != nil {
				return fmt.Errorf("failed to add alias relationship %s -> %s: %w", identifier.Value, advisory.GhsaID, err)
			}
			err = db.AddAlias(identifier.Value, advisory.GhsaID, source)
			if err != nil {
				return fmt.Errorf("failed to add alias relationship %s -> %s: %w", advisory.GhsaID, identifier.Value, err)
			}
		}
	}

	return nil
}

type securityAdvisory struct {
	ID          string
	GhsaID      string
	Identifiers []struct {
		Type  string
		Value string
	}
}

func getAdvisories(ctx context.Context, logger zerolog.Logger, client *githubv4.Client) (<-chan securityAdvisory, <-chan error) {
	advisoryChan := make(chan securityAdvisory, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer func() {
			close(advisoryChan)
			close(errorChan)
		}()

		queryParams := make(map[string]any)
		queryParams["cursor"] = (*githubv4.String)(nil)

		for {
			select {
			case <-ctx.Done():
				logger.Warn().Err(ctx.Err()).Msg("aborted")
				return
			default:
			}

			var query struct {
				SecurityAdvisories struct {
					Nodes    []securityAdvisory
					PageInfo struct {
						EndCursor   githubv4.String
						HasNextPage bool
					}
				} `graphql:"securityAdvisories(first: 100, after: $cursor)"`
			}

			err := client.Query(ctx, &query, queryParams)
			if err != nil {
				errorChan <- fmt.Errorf("failed to query security advisories: %w", err)
				return
			}

			for _, advisory := range query.SecurityAdvisories.Nodes {
				advisoryChan <- advisory
			}

			if !query.SecurityAdvisories.PageInfo.HasNextPage {
				return
			}

			queryParams["cursor"] = query.SecurityAdvisories.PageInfo.EndCursor
		}
	}()

	return advisoryChan, errorChan
}
