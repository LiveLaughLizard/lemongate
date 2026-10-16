// Package store provides typed access to core management entities.
package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

type Store struct{ Pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

func queryAll[T any](ctx context.Context, s *Store, sql string, args ...any) ([]T, error) {
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[T])
	if out == nil {
		out = []T{}
	}
	return out, err
}

func queryOne[T any](ctx context.Context, s *Store, sql string, args ...any) (T, error) {
	rows, err := s.Pool.Query(ctx, sql, args...)
	var zero T
	if err != nil {
		return zero, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByNameLax[T])
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, ErrNotFound
	}
	return v, err
}

func mapErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

func exec(ctx context.Context, s *Store, sql string, args ...any) error {
	tag, err := s.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 && (strings.HasPrefix(strings.TrimSpace(sql), "UPDATE") || strings.HasPrefix(strings.TrimSpace(sql), "DELETE")) {
		return ErrNotFound
	}
	return nil
}

// Nullable helpers for optional foreign keys coming from forms.
func NullIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func Deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func CleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
