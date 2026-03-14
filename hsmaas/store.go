package hsmaas

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/lib/pq"
)

// PolicyStore fetches and sets key policies by key ID and role.
// Implement this interface to plug in your own policy storage (e.g. DB, in-memory, API).
type PolicyStore interface {
	FetchPolicy(ctx context.Context, keyID, role string) (*Policy, error)
	// SetPolicy creates or updates the policy for the given key and role.
	SetPolicy(ctx context.Context, keyID, role string, policy *Policy) error
}

// PostgresPolicyStore implements PolicyStore using a PostgreSQL table with a JSONB policy column.
type PostgresPolicyStore struct {
	db *sql.DB
}

// NewPostgresPolicyStore opens a connection to the database and returns a PolicyStore.
// It creates the policies table if it does not exist.
func NewPostgresPolicyStore(dsn string) (*PostgresPolicyStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PostgresPolicyStore{db: db}
	if err := s.ensureTable(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *PostgresPolicyStore) ensureTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS policies (
		id SERIAL PRIMARY KEY,
		key_id VARCHAR(255) NOT NULL,
		role VARCHAR(255) NOT NULL,
		policy JSONB NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("create policies table: %w", err)
	}
	// Unique index for upsert (SetPolicy); safe for new and existing tables
	if _, err := s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS policies_key_id_role_idx ON policies(key_id, role)`); err != nil {
		return fmt.Errorf("create unique index: %w", err)
	}
	return nil
}

// FetchPolicy returns the policy for the given key ID and role, or ErrPolicyNotFound.
func (s *PostgresPolicyStore) FetchPolicy(ctx context.Context, keyID, role string) (*Policy, error) {
	var raw []byte
	query := `SELECT policy FROM policies WHERE key_id = $1 AND role = $2`
	err := s.db.QueryRowContext(ctx, query, keyID, role).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("fetch policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}
	return &p, nil
}

// SetPolicy creates or updates the policy for the given key and role.
func (s *PostgresPolicyStore) SetPolicy(ctx context.Context, keyID, role string, policy *Policy) error {
	raw, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	query := `
		INSERT INTO policies (key_id, role, policy) VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (key_id, role) DO UPDATE SET policy = EXCLUDED.policy, updated_at = CURRENT_TIMESTAMP`
	if _, err := s.db.ExecContext(ctx, query, keyID, role, raw); err != nil {
		return fmt.Errorf("set policy: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (s *PostgresPolicyStore) Close() error {
	return s.db.Close()
}
