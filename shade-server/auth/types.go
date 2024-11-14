package auth

import (
	"math/big"
	"time"
)

type DHParams struct {
	Prime        *big.Int
	Generator    *big.Int
	PrivateKey   *big.Int
	PublicKey    *big.Int
	SharedSecret *big.Int
}

type Session struct {
	SessionID string    `json:"sessionId"`
	DID       string    `json:"did"`
	CreatedAt time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type DIDDocument struct {
	Context        string `json:"@context"`
	ID             string `json:"id"`
	Authentication []struct {
		Type         string `json:"type"`
		PublicKeyHex string `json:"publicKeyHex"`
	} `json:"authenticaton"`
	Service []interface{} `json:"service"`
}
