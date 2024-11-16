package types

import (
	"crypto/ecdh"
	"crypto/ecdsa"

	"time"

	"context"
	"github.com/google/uuid"
)

type KeyPairECDSA struct {
	PrivateKeyECDSA *ecdsa.PrivateKey
	PublicKeyECDSA  *ecdsa.PublicKey
}

type KeyPairECDH struct {
	PrivateKeyECDH *ecdh.PrivateKey
	PublicKeyECDH  *ecdh.PublicKey
}

type ECDHSharedSecret struct {
	SharedSecret []byte
}

type ChallengeSession struct {
	ID                  uuid.UUID
	DID                 string
	Challenge           []byte
	EncryptedChallenge  []byte
	EphemeralPrivateKey []byte // Store private key for ECDH
	EphemeralPublicKey  []byte
	SharedSecret1       []byte // ECDH with identity keys
	SharedSecret2       []byte // ECDH with ephemeral keys
	Salt                []byte
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Status              string // pending, completed, expired
}

type AuthSession struct {
	ID         uuid.UUID
	DID        string
	SessionKey []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Status     string // active, expired, revoked
}

type Database interface {
	// Challenge Session operations
	CreateChallengeSession(ctx context.Context, session *ChallengeSession) error
	GetChallengeSession(ctx context.Context, id uuid.UUID) (*ChallengeSession, error)
	GetPendingChallengeSessionsByDID(ctx context.Context, did string) ([]*ChallengeSession, error)
	UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status string) error
	DeleteExpiredChallengeSessions(ctx context.Context) error

	// Auth Session operations
	CreateAuthSession(ctx context.Context, session *AuthSession) error
	GetAuthSession(ctx context.Context, id uuid.UUID) (*AuthSession, error)
	GetActiveAuthSessionsByDID(ctx context.Context, did string) ([]*AuthSession, error)
	UpdateAuthSessionStatus(ctx context.Context, id uuid.UUID, status string) error
	DeleteExpiredAuthSessions(ctx context.Context) error

	Close() error
}

// Request/Response types
type ChallengeRequest struct {
	DID string `json:"did" binding:"required"`
}

type ChallengeResponse struct {
	SessionID          string `json:"session_id"`
	Challenge          []byte `json:"challenge"`
	EncryptedChallenge []byte `json:"encrypted_challenge"`
	EphemeralPublicKey []byte `json:"ephemeral_public_key"`
	Salt               []byte `json:"salt"`
	ExpiresAt          int64  `json:"expires_at"`
}

type VerifyRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	Signature []byte `json:"signature" binding:"required"`
}

type VerifyResponse struct {
	SessionKey []byte `json:"session_key"`
	ExpiresAt  int64  `json:"expires_at"`
}
