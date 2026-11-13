package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type schemaRow struct {
	ready bool
	err   error
}

func (r schemaRow) Scan(values ...any) error {
	if r.err != nil {
		return r.err
	}
	*values[0].(*bool) = r.ready
	return nil
}

type schemaQuery struct {
	t   *testing.T
	row schemaRow
}

func (q schemaQuery) QueryRow(ctx context.Context, sql string, _ ...any) pgx.Row {
	q.t.Helper()
	if _, ok := ctx.Deadline(); !ok {
		q.t.Error("startup schema check has no timeout")
	}
	if !strings.Contains(sql, "pg_trigger") || !strings.Contains(sql, "authorization_revision") {
		q.t.Error("schema check must verify column and revision triggers")
	}
	return q.row
}

func TestAuthorizationSchemaStartupGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  schemaRow
		fail bool
	}{
		{"migrated", schemaRow{ready: true}, false},
		{"missing migration or disabled triggers", schemaRow{}, true},
		{"database unavailable", schemaRow{err: errors.New("secret connection details")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireAuthorizationSchema(context.Background(), schemaQuery{t, tc.row}, time.Second)
			if (err != nil) != tc.fail {
				t.Fatalf("startup error=%v, failure expected=%v", err, tc.fail)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("driver details disclosed")
			}
		})
	}
}
