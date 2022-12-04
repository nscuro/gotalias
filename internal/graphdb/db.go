package graphdb

import (
	"context"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type DB struct {
	ns neo4j.SessionWithContext
}

func New(ns neo4j.SessionWithContext) *DB {
	return &DB{ns: ns}
}

func (d DB) AddVulnerability(id string) error {
	return d.DoInTx(context.TODO(), func(ctx context.Context, tx neo4j.ExplicitTransaction) error {
		_, err := tx.Run(ctx, `MERGE (:Vulnerability {id: $id})`, map[string]any{"id": id})
		return err
	})
}

func (d DB) AddAlias(id, alias, reportedBy string) error {
	return d.DoInTx(context.TODO(), func(ctx context.Context, tx neo4j.ExplicitTransaction) error {
		_, err := tx.Run(ctx, `
MATCH (a:Vulnerability {id:$id}), (b:Vulnerability{id:$alias}) 
MERGE (a)<-[r:ALIASES]-(b)
WITH r, COALESCE(r.reportedBy, []) + $reportedBy AS reportedBy
UNWIND reportedBy AS rb
WITH r, COLLECT(DISTINCT rb) AS uniqueRb
SET r.reportedBy = uniqueRb`,
			map[string]any{"id": id, "alias": alias, "reportedBy": reportedBy})
		return err
	})
}

func (d DB) AddCVSS(id string, score float64, vector, reportedBy string) error {
	return d.DoInTx(context.TODO(), func(ctx context.Context, tx neo4j.ExplicitTransaction) error {
		_, err := tx.Run(ctx, `
MATCH (v:Vulnerability {id:$id})
MERGE (:Cvss {score: $score, vector: $vector})-[r:DESCRIBES]->(v)
WITH r, COALESCE(r.reportedBy, []) + $reportedBy AS reportedBy
UNWIND reportedBy AS rb
WITH r, COLLECT(DISTINCT rb) AS uniqueRb
SET r.reportedBy = uniqueRb`,
			map[string]any{"id": id, "score": score, "vector": vector, "reportedBy": reportedBy})
		return err
	})
}

func (d DB) AddCWE(id, cwe, reportedBy string) error {
	if !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
		cwe = "CWE-" + cwe
	}
	return d.DoInTx(context.TODO(), func(ctx context.Context, tx neo4j.ExplicitTransaction) error {
		_, err := tx.Run(ctx, `
MATCH (v:Vulnerability {id:$id})
MERGE (:Cwe {id: $cwe})-[r:DESCRIBES]->(v)
WITH r, COALESCE(r.reportedBy, []) + $reportedBy AS reportedBy
UNWIND reportedBy AS rb
WITH r, COLLECT(DISTINCT rb) AS uniqueRb
SET r.reportedBy = uniqueRb`,
			map[string]any{"id": id, "cwe": cwe, "reportedBy": reportedBy})
		return err
	})
}

func (d DB) DoInTx(ctx context.Context, f func(ctx context.Context, tx neo4j.ExplicitTransaction) error) error {
	tx, err := d.ns.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Close(ctx)

	err = f(ctx, tx)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
