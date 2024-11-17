package database

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"context"
	"shade-server/types"
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := initializeTables(db); err != nil {
		return nil, err
	}

	return &SQLiteDB{db: db}, nil
}

func initializeTables(db *sql.DB) error {
	schema := `
    CREATE TABLE IF NOT EXISTS challenge_sessions (
        id TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        challenge BLOB NOT NULL,
        encrypted_challenge BLOB NOT NULL,
        ephemeral_private_key BLOB NOT NULL,
        ephemeral_public_key BLOB NOT NULL,
        shared_secret1 BLOB,
        shared_secret2 BLOB,
        salt BLOB NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        status TEXT CHECK (status IN ('pending', 'completed', 'expired')) DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS auth_sessions (
        id TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        session_key BLOB NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        status TEXT CHECK (status IN ('active', 'expired', 'revoked')) DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS server_keys (
        did TEXT PRIMARY KEY,
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_challenge_sessions_did ON challenge_sessions(did);
    CREATE INDEX IF NOT EXISTS idx_auth_sessions_did ON auth_sessions(did);`

	_, err := db.Exec(schema)
	return err
}

func (db *SQLiteDB) GetServerKeys(ctx context.Context) (*types.ServerKeys, error) {
	var keys types.ServerKeys
	row := db.db.QueryRowContext(ctx, "SELECT did, private_key, public_key FROM server_keys LIMIT 1")
	err := row.Scan(&keys.DID, &keys.PrivateKey, &keys.PublicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &keys, nil
}

func (db *SQLiteDB) SaveServerKeys(ctx context.Context, keys *types.ServerKeys) error {
	query := `INSERT OR REPLACE INTO server_keys (did, private_key, public_key) VALUES (?, ?, ?)`
	_, err := db.db.ExecContext(ctx, query, keys.DID, keys.PrivateKey, keys.PublicKey)
	return err
}
