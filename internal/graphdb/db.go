package graphdb

import (
	"context"
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
