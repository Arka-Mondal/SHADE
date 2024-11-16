package database

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"shade-server/types"
	"time"
)

func (db *SQLiteDB) CreateChallengeSession(ctx context.Context, session *types.ChallengeSession) error {
	query := `
        INSERT INTO challenge_sessions (
            id, did, challenge, encrypted_challenge, 
            ephemeral_private_key, ephemeral_public_key,
            shared_secret1, shared_secret2, salt,
            created_at, expires_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.db.ExecContext(ctx, query,
		session.ID.String(),
		session.DID,
		session.Challenge,
		session.EncryptedChallenge,
		session.EphemeralPrivateKey,
		session.EphemeralPublicKey,
		session.SharedSecret1,
		session.SharedSecret2,
		session.Salt,
		session.CreatedAt,
		session.ExpiresAt,
		session.Status)

	return err
}

func (db *SQLiteDB) GetChallengeSession(ctx context.Context, id uuid.UUID) (*types.ChallengeSession, error) {
	query := `SELECT * FROM challenge_sessions WHERE id = ?`

	var session types.ChallengeSession
	var idStr string

	err := db.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&session.DID,
		&session.Challenge,
		&session.EncryptedChallenge,
		&session.EphemeralPrivateKey,
		&session.EphemeralPublicKey,
		&session.SharedSecret1,
		&session.SharedSecret2,
		&session.Salt,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Status,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	session.ID = uuid.MustParse(idStr)
	return &session, nil
}

func (db *SQLiteDB) GetPendingChallengeSessionsByDID(ctx context.Context, did string) ([]*types.ChallengeSession, error) {
	query := `
        SELECT * FROM challenge_sessions 
        WHERE did = ? AND status = 'pending' AND expires_at > ?`

	rows, err := db.db.QueryContext(ctx, query, did, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*types.ChallengeSession
	for rows.Next() {
		var session types.ChallengeSession
		var idStr string
		err := rows.Scan(
			&idStr,
			&session.DID,
			&session.Challenge,
			&session.EncryptedChallenge,
			&session.EphemeralPrivateKey,
			&session.EphemeralPublicKey,
			&session.SharedSecret1,
			&session.SharedSecret2,
			&session.Salt,
			&session.CreatedAt,
			&session.ExpiresAt,
			&session.Status,
		)
		if err != nil {
			return nil, err
		}
		session.ID = uuid.MustParse(idStr)
		sessions = append(sessions, &session)
	}
	return sessions, nil
}

func (db *SQLiteDB) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE challenge_sessions SET status = ? WHERE id = ?`
	result, err := db.db.ExecContext(ctx, query, status, id.String())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *SQLiteDB) DeleteExpiredChallengeSessions(ctx context.Context) error {
	query := `DELETE FROM challenge_sessions WHERE expires_at < ?`
	_, err := db.db.ExecContext(ctx, query, time.Now())
	return err
}

func (db *SQLiteDB) Close() error {
	return db.db.Close()
}

func (db *SQLiteDB) CreateAuthSession(ctx context.Context, session *types.AuthSession) error {
	query := `
        INSERT INTO auth_sessions (
            id, did, session_key, created_at, expires_at, status
        ) VALUES (?, ?, ?, ?, ?, ?)`

	_, err := db.db.ExecContext(ctx, query,
		session.ID.String(),
		session.DID,
		session.SessionKey,
		session.CreatedAt,
		session.ExpiresAt,
		session.Status)

	return err
}

func (db *SQLiteDB) GetAuthSession(ctx context.Context, id uuid.UUID) (*types.AuthSession, error) {
	query := `SELECT * FROM auth_sessions WHERE id = ?`

	var session types.AuthSession
	var idStr string

	err := db.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&session.DID,
		&session.SessionKey,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Status,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	session.ID = uuid.MustParse(idStr)
	return &session, nil
}

func (db *SQLiteDB) GetActiveAuthSessionsByDID(ctx context.Context, did string) ([]*types.AuthSession, error) {
	query := `
        SELECT * FROM auth_sessions 
        WHERE did = ? AND status = 'active' AND expires_at > ?`

	rows, err := db.db.QueryContext(ctx, query, did, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*types.AuthSession
	for rows.Next() {
		var session types.AuthSession
		var idStr string
		err := rows.Scan(
			&idStr,
			&session.DID,
			&session.SessionKey,
			&session.CreatedAt,
			&session.ExpiresAt,
			&session.Status,
		)
		if err != nil {
			return nil, err
		}
		session.ID = uuid.MustParse(idStr)
		sessions = append(sessions, &session)
	}
	return sessions, nil
}

func (db *SQLiteDB) UpdateAuthSessionStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE auth_sessions SET status = ? WHERE id = ?`
	result, err := db.db.ExecContext(ctx, query, status, id.String())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *SQLiteDB) DeleteExpiredAuthSessions(ctx context.Context) error {
	query := `DELETE FROM auth_sessions WHERE expires_at < ?`
	_, err := db.db.ExecContext(ctx, query, time.Now())
	return err
}
