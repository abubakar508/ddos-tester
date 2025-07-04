package db

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"
)

type Store struct {
	DB *sql.DB
}

func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) SaveTestResult(ctx context.Context, url string, count, concurrency int, durationMs int64, successCount int) error {
	query := `INSERT INTO load_tests (url, count, concurrency, duration_ms, success_count, created_at)
              VALUES ($1, $2, $3, $4, $5, NOW())`
	_, err := s.DB.ExecContext(ctx, query, url, count, concurrency, durationMs, successCount)
	return err
}
