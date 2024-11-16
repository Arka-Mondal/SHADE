package database

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
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

    CREATE INDEX IF NOT EXISTS idx_challenge_sessions_did ON challenge_sessions(did);
    CREATE INDEX IF NOT EXISTS idx_auth_sessions_did ON auth_sessions(did);`

	_, err := db.Exec(schema)
	return err
}
