package server

import (
	"crypto/rand"
	_"encoding/hex"
	"fmt"
	"net/http"
	"shade-server/auth"
	"shade-server/types"
	"time"

	"log"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Server) CreateChallenge(c *gin.Context, req types.ChallengeRequest) (*types.ChallengeSession, error) {
	// First, verify the DID exists and is active by fetching the DID Document
	log.Printf("Fetching DID Document for DID: %s", req.DID)
	didDoc, err := s.contract.GetDIDDocument(req.DID)
	if err != nil {
		log.Printf("Error fetching DID Document: %v", err)
		return nil, fmt.Errorf("failed to verify DID: %v", err)
	}

	// Verify DID is active
	if !didDoc.Active {
		log.Printf("DID %s is not active", didDoc.DID)
		return nil, fmt.Errorf("DID is not active")
	}

	log.Printf("DID Document found and verified. Public Key: %s", didDoc.PublicKey)

	// Generate ephemeral key pair for the challenge
	keyPair, err := auth.GenerateECCKeyPair()
	if err != nil {
		log.Printf("Failed to generate keys: %v", err)
		return nil, err
	}

	// Generate random challenge
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		log.Printf("Failed to generate challenge: %v", err)
		return nil, err
	}

	encodedPrivateKey, err := auth.EncodePrivateKeyToBytes(keyPair.PrivateKeyECDSA)
	if err != nil {
		log.Printf("Failed to encode private key: %v", err)
		return nil, err
	}

	encodedPublicKey, err := auth.EncodePublicKeyToBytes(keyPair.PublicKeyECDSA)
	if err != nil {
		log.Printf("Failed to encode public key: %v", err)
		return nil, err
	}

	if len(encodedPrivateKey) > 0 && encodedPrivateKey[len(encodedPrivateKey)-1] == '\n' {
		encodedPrivateKey = encodedPrivateKey[:len(encodedPrivateKey)-1]
	}

	if len(encodedPublicKey) > 0 && encodedPublicKey[len(encodedPublicKey)-1] == '\n' {
		encodedPublicKey = encodedPublicKey[:len(encodedPublicKey)-1]
	}

	// client's ephemeral public key
	// fmt.Printf("%s\n", req.EphemeralPublicKey)
	// ephemeralClientPublicKey, err := hex.DecodeString(req.EphemeralPublicKey)
	// if err != nil {
	// 	log.Printf("Failed to decode ephemeral public key: %v", err)
	// 	return nil, err
	// }

	decodedEphemeralClientPublicKey, err := auth.DecodePublicKeyFromBytes([]byte(req.EphemeralPublicKey))
	if err != nil {
		log.Printf("Failed to decode ephemeral public key: %v", err)
		return nil, err
	}

	// fmt.Printf("Decoded ephemeral public key: %s\n", decodedEphemeralClientPublicKey)


	// client's identity public key
	// identityClientPublicKey, err := hex.DecodeString(didDoc.PublicKey)
	// if err != nil {
	// 	log.Printf("Failed to decode identity public key: %v", err)
	// 	return nil, err
	// }

	decodedIdentityClientPublicKey, err := auth.DecodePublicKeyFromBytes([]byte(didDoc.PublicKey))
	if err != nil {
		log.Printf("Failed to decode identity public key: %v", err)
		return nil, err
	}

	// Fetch server's private key
	serverKey, err := s.db.GetServerKeys(c.Request.Context())
	if err != nil {
		log.Printf("Failed to fetch server private key: %v", err)
		return nil, err
	}

	decodedIndentityServerPrivateKey, err := auth.DecodePrivateKeyFromBytes(serverKey.PrivateKey)
	if err != nil {
		log.Printf("Failed to decode server private key: %v", err)
		return nil, err
	}

	sharedSecret_eph, err := auth.ECDHComputeSharedSecret(keyPair.PrivateKeyECDSA, decodedEphemeralClientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return nil, err
	}

	sharedSecret_id, err := auth.ECDHComputeSharedSecret(decodedIndentityServerPrivateKey, decodedIdentityClientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return nil, err
	}

	key, salt, err := auth.DeriveKey(sharedSecret_id, sharedSecret_eph, nil)
	if err != nil {
		log.Printf("Failed to derive key: %v", err)
		return nil, err
	}

	encryptedChallenge, err := auth.Encrypt(key, challenge)
	if err != nil {
		log.Printf("Failed to encrypt challenge: %v", err)
		return nil, err
	}

	// Create challenge session with verified DID
	session := &types.ChallengeSession{
		ID:                  uuid.New(),
		DID:                 didDoc.DID,
		Challenge:           challenge,
		EncryptedChallenge:  encryptedChallenge,
		EphemeralPrivateKey: encodedPrivateKey,
		EphemeralPublicKey:  encodedPublicKey,
		SharedSecret1:       sharedSecret_id.SharedSecret,
		SharedSecret2:       sharedSecret_eph.SharedSecret,
		Salt:                salt,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		Status:              "pending",
	}

	log.Printf("Created challenge session for DID %s with ID %s", didDoc.DID, session.ID)
	return session, nil
}

func (s *Server) handleChallenge(c *gin.Context) {
	var req types.ChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	session, err := s.CreateChallenge(c, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := s.db.CreateChallengeSession(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, types.ChallengeResponse{
		SessionID:          session.ID.String(),
		EncryptedChallenge: session.EncryptedChallenge,
		EphemeralPublicKey: session.EphemeralPublicKey,
		Salt:               session.Salt,
		ExpiresAt:          session.ExpiresAt.Unix(),
	})
}

func (s *Server) handleVerify(c *gin.Context) {
	return
}
