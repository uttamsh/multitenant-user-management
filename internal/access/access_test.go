package access

import (
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

func TestDatabaseErrorMapping(t *testing.T) {
	for _, code := range []string{"23505", "23503", "40001", "40P01"} {
		if !errors.Is(DBError(&pgconn.PgError{Code: code}), ErrConflict) {
			t.Fatal("database conflict was not mapped")
		}
	}
	for _, code := range []string{"22P02", "23514", "22001"} {
		if !errors.Is(DBError(&pgconn.PgError{Code: code}), ErrInvalid) {
			t.Fatal("invalid input was not mapped")
		}
	}
	if !errors.Is(DBError(pgx.ErrNoRows), ErrNotFound) {
		t.Fatal("missing resource was not mapped")
	}
}
