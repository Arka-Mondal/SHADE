package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
  "math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"shade-server/auth"
)

type Server struct {
	DHParams      *auth.DHParams
	sessions      map[string]*auth.Session
	challenges    map[string][]byte
	sessionMutex  sync.RWMutex
	EncryptionKey []byte
}

func New() (*Server, error) {
	dhParams, err := auth.GenerateDHParameters(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH params: %v", err)
	}

	return &Server{
		DHParams:   dhParams,
		sessions:   make(map[string]*auth.Session),
		challenges: make(map[string][]byte),
	}, nil
}

func (s *Server) HandleDHKE(ctx context.Context, clientPubKey *big.Int) error {
	err := s.DHParams.ComputeSharedSecret(clientPubKey)
	if err != nil {
		return fmt.Errorf("failed to comput shared secret: %v", err)
	}

	key, err := s.DHParams.DeriveKey()
	if err != nil {
		return fmt.Errorf("failed to derive key: %v", err)
	}

	s.EncryptionKey = key

	return nil
}

func (s *Server) GenerateChallenge(did string) ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %v", err)
	}

	s.challenges[did] = challenge

	return challenge, nil
}

func (s *Server) VerifySignature(did string, encryptedSig []byte, pubKey *ecdsa.PublicKey) error {
	signature, err := auth.Decrypt(s.EncryptionKey, encryptedSig)
	if err != nil {
		return fmt.Errorf("failed to decrypt signature: %v", err)
	}

	challenge, exists := s.challenges[did]
	if !exists {
		return fmt.Errorf("no challenge found for DID")
	}

	// verify signature
	if !auth.VerifySignature(pubKey, challenge, signature) {
		return fmt.Errorf("invalid signature")
	}

	delete(s.challenges, did)
	return nil
}

func (s *Server) CreateSession(did string) (*auth.Session, error) {
	sessionID := uuid.New().String()
	session := &auth.Session{
		SessionID: sessionID,
		DID:       did,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	s.sessionMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionMutex.Unlock()

	return session, nil
}

func (s *Server) ValidateSession(sessionID string) bool {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return false
	}

	return time.Now().Before(session.ExpiresAt)
}
