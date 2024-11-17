package server

import (
	"crypto/rand"
	"net/http"
	"shade-server/auth"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"shade-server/types"
)

func (s *Server) handleChallenge(c *gin.Context) {
	var req types.ChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Generate ephemeral key pair
	keyPair, err := auth.GenerateECCKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate keys"})
		return
	}

	// Generate random challenge
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate challenge"})
		return
	}

	encodedPrivateKey, err := auth.EncodePrivateKeyToBytes(keyPair.PrivateKeyECDSA)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode private key"})
		return
	}

	encodedPublicKey, err := auth.EncodePublicKeyToBytes(keyPair.PublicKeyECDSA)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode public key"})
		return
	}

	if len(encodedPrivateKey) > 0 && encodedPrivateKey[len(encodedPrivateKey)-1] == '\n' {
		encodedPrivateKey = encodedPrivateKey[:len(encodedPrivateKey)-1]
	}

	if len(encodedPublicKey) > 0 && encodedPublicKey[len(encodedPublicKey)-1] == '\n' {
		encodedPublicKey = encodedPublicKey[:len(encodedPublicKey)-1]
	}

	// Create challenge session
	session := &types.ChallengeSession{
		ID:                  uuid.New(),
		DID:                 req.DID,
		Challenge:           challenge,
		EphemeralPrivateKey: encodedPrivateKey,
		EphemeralPublicKey:  encodedPublicKey,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		Status:              "pending",
	}

	if err := s.db.CreateChallengeSession(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, types.ChallengeResponse{
		SessionID:          session.ID.String(),
		Challenge:          session.Challenge,
		EphemeralPublicKey: session.EphemeralPublicKey,
		ExpiresAt:          session.ExpiresAt.Unix(),
	})
}

func (s *Server) handleVerify(c *gin.Context) {
	return
}
