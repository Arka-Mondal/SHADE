package server

import (
	"crypto/rand"
	"encoding/base64"
	_ "encoding/hex"
	"fmt"
	"net/http"
	"shade-server/auth"
	"shade-server/types"
	"time"

	"log"

	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func JsonEnc(pemKey []byte) string {
	encoded := base64.StdEncoding.EncodeToString(pemKey)
	return encoded
}

func JsonDec(encKey string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		fmt.Printf("Error decoding: %v\n", err)
		return nil
	}

	return decoded
}

func (s *Server) CreateChallenge(c *gin.Context, req types.ChallengeRequest) (*types.ChallengeSession, *types.ServerKeys, error) {
	// First, verify the DID exists and is active by fetching the DID Document
	log.Printf("Fetching DID Document for DID: %s", req.DID)
	didDoc, err := s.contract.GetDIDDocument(req.DID)
	if err != nil {
		log.Printf("Error fetching DID Document: %v", err)
		return nil, nil, fmt.Errorf("failed to verify DID: %v", err)
	}

	// Verify DID is active
	if !didDoc.Active {
		log.Printf("DID %s is not active", didDoc.DID)
		return nil, nil, fmt.Errorf("DID is not active")
	}

	log.Printf("DID Document found and verified. Public Key: %s", didDoc.PublicKey)

	// Generate ephemeral key pair for the challenge
	keyPair, err := auth.GenerateECCKeyPair()
	if err != nil {
		log.Printf("Failed to generate keys: %v", err)
		return nil, nil, err
	}

	// Generate random challenge
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		log.Printf("Failed to generate challenge: %v", err)
		return nil, nil, err
	}

	encodedPrivateKey, err := auth.EncodePrivateKeyToBytes(keyPair.PrivateKeyECDSA)
	if err != nil {
		log.Printf("Failed to encode private key: %v", err)
		return nil, nil, err
	}

	encodedPublicKey, err := auth.EncodePublicKeyToBytes(keyPair.PublicKeyECDSA)
	if err != nil {
		log.Printf("Failed to encode public key: %v", err)
		return nil, nil, err
	}

	fmt.Printf("%v\n", encodedPublicKey)

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
		return nil, nil, err
	}

	// fmt.Printf("hello hello hello enc %s\n", req.EphemeralPublicKey)

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
		return nil, nil, err
	}

	// fmt.Printf("Client ID Pub key: %\n", didDoc.PublicKey)

	// Fetch server's private key
	serverKey, err := s.db.GetServerKeys(c.Request.Context())
	if err != nil {
		log.Printf("Failed to fetch server private key: %v", err)
		return nil, nil, err
	}

	fmt.Printf("My own id pub key: %s\n", serverKey.PublicKey)

	decodedIndentityServerPrivateKey, err := auth.DecodePrivateKeyFromBytes(serverKey.PrivateKey)
	if err != nil {
		log.Printf("Failed to decode server private key: %v", err)
		return nil, nil, err
	}

	sharedSecret_eph, err := auth.ECDHComputeSharedSecret(keyPair.PrivateKeyECDSA, decodedEphemeralClientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return nil, nil, err
	}

	sharedSecret_id, err := auth.ECDHComputeSharedSecret(decodedIndentityServerPrivateKey, decodedIdentityClientPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return nil, nil, err
	}

	key, salt, err := auth.DeriveKey(sharedSecret_id, sharedSecret_eph, nil)
	if err != nil {
		log.Printf("Failed to derive key: %v", err)
		return nil, nil, err
	}

	encryptedChallenge, err := auth.Encrypt(key, challenge)
	if err != nil {
		log.Printf("Failed to encrypt challenge: %v", err)
		return nil, nil, err
	}

	fmt.Printf("enc Key Id %v\n", sharedSecret_id.SharedSecret)
	fmt.Printf("enc Key EPh %v\n", sharedSecret_eph.SharedSecret)
	fmt.Printf("enc Key salt: %v\n", salt)
	fmt.Printf("enc Key key: %v\n", key)
	fmt.Printf("enc Key encChallenge: %v\n", encryptedChallenge)
	// challengeDec, _ := hex.DecodeString(string(challenge))
	fmt.Printf("enc Key Challenge: %v\n", challenge)

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
	return session, serverKey, nil
}

func (s *Server) handleChallenge(c *gin.Context) {
	var req types.ChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	session, serverKey, err := s.CreateChallenge(c, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := s.db.CreateChallengeSession(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// fmt.Printf("enc %s\n", session.EphemeralPublicKey)
	// fmt.Printf("enc %v\n", session.Salt)
	// fmt.Printf("enc %v\n", session.EncryptedChallenge)
	// encodedEphemeralPublicKey := []byte(JsonEnc(session.EphemeralPublicKey))

	fmt.Printf("session salt: %v\n", session.Salt)
	fmt.Printf("session salt: %v\n", JsonEnc(session.Salt))

	c.JSON(http.StatusOK, types.ChallengeResponse{
		SessionID:          session.ID.String(),
		EncryptedChallenge: session.EncryptedChallenge,
		EphemeralPublicKey: session.EphemeralPublicKey,
		Did:                serverKey.DID,
		Salt:               session.Salt,
		ExpiresAt:          session.ExpiresAt.Unix(),
	})

	// json.RawMessage(`"` + session.EphemeralPublicKey + `"`)
	// fmt.Printf("hello hello hello enc %s\n", session.EphemeralPublicKey)

}

func (s *Server) handleVerify(c *gin.Context) {
	var req types.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Retrieve the session from the database
	session, err := s.db.GetChallengeSession(c.Request.Context(), uuid.MustParse(req.SessionID))
	if err != nil {
		log.Printf("Failed to retrieve session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session"})
		return
	}
	if session == nil {
		log.Printf("Session not found for SessionID: %s", req.SessionID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session not found"})
		return
	}

	// Check if the challenge matches the database record
	if !bytes.Equal(session.Challenge, JsonDec(req.Challenge)) {
		log.Printf("Invalid challenge for SessionID: %s", req.SessionID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge"})
		return
	}

	if !bytes.Equal([]byte(session.DID), []byte(req.Did)) {
		log.Printf("Invalid DID for SessionID: %s. Expected: %v, Received: %v", req.SessionID, session.DID, req.Did)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid DID"})
		return
	}

	// Fetch the DID Document from the blockchain
	didDoc, err := s.contract.GetDIDDocument(session.DID)
	if err != nil {
		log.Printf("Failed to fetch DID Document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DID Document"})
		return
	}

	// Decode the identity client's public key from the DID Document
	decodedIdentityClientPublicKey, err := auth.DecodePublicKeyFromBytes([]byte(didDoc.PublicKey))
	if err != nil {
		log.Printf("Failed to decode identity public key: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to decode identity public key"})
		return
	}

	log.Printf("Client ID Public Key: %v", didDoc.PublicKey)

	decodedSignature := JsonDec(req.Signature)
	decodedChallenge := JsonDec(req.Challenge)
	log.Printf("Decoded Signature: %v", decodedSignature)
	log.Printf("Decoded Challenge: %v", decodedChallenge)

	log.Printf("Original Challenge from Session: %x", session.Challenge)
	log.Printf("Received Challenge (decoded): %x", JsonDec(req.Challenge))
	log.Printf("Signature (decoded): %x", JsonDec(req.Signature))
	log.Printf("Public Key used for verification: %s", didDoc.PublicKey)

	status, err := auth.VerifySignature(decodedIdentityClientPublicKey, decodedChallenge, decodedSignature)
	if err != nil {
		log.Printf("Failed to verify signature: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify signature"})
		return
	}

	sendStatus := "failure"
	if status {
		sendStatus = "success"
	}

	c.JSON(http.StatusOK, types.VerifyResponse{
		Status:     sendStatus,
		SessionKey: []byte{},
		ExpiresAt:  time.Now().Unix(),
	})
}
