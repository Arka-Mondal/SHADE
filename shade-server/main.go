package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"shade-server/auth"
	"shade-server/blockchain"
	"shade-server/database"
	"shade-server/server"
	"shade-server/types"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joho/godotenv"
)

const (
	BaseSepoliaRPC = "https://sepolia.base.org"
	ContractAddress = "0x355c6412Dd7f3e3A837ca5833D2E66f4046F09E4"
)

func main() {
	log.Printf("Starting Shade Server at %s", time.Now().Format(time.RFC3339))
	err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

	// Initialize database
	log.Printf("Initializing database connection...")
	db, err := database.NewSQLiteDB("./shade.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Printf("Database connection established successfully")

	// Initialize blockchain contract
	log.Printf("Loading contract ABI...")
	contractABI := loadContractABI()
	log.Printf("Initializing Identity Registry contract at address: %s", ContractAddress)
	registry, err := blockchain.NewIdentityRegistry(BaseSepoliaRPC, ContractAddress, contractABI)
	if err != nil {
		log.Fatalf("Failed to initialize contract: %v", err)
	}
	log.Printf("Contract initialization successful")

	// Initialize server identity
	log.Printf("Initializing server identity...")
	if err := initializeServerIdentity(db, registry); err != nil {
		log.Fatalf("Failed to initialize server identity: %v", err)
	}
	log.Printf("Server identity initialized successfully")

	log.Printf("Starting HTTP server on port 8080...")
	server := server.NewServer(db)
	server.Start(":8080")
}

func initializeServerIdentity(db types.Database, registry *blockchain.IdentityRegistry) error {
	ctx := context.Background()
	
	log.Printf("Checking for existing server keys...")
	serverKeys, err := db.GetServerKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server keys: %w", err)
	}

	if serverKeys != nil {
		log.Printf("Found existing server keys with DID: %s", serverKeys.DID)
		// Verify DID is still valid
		log.Printf("Verifying DID validity on blockchain...")
		isValid, err := registry.IsValidDID(serverKeys.DID)
		if err != nil {
			return fmt.Errorf("failed to verify DID validity: %w", err)
		}
		if isValid {
			log.Printf("Existing DID is valid")
			return nil
		}
		log.Printf("Existing DID is invalid, generating new identity")
	}

	// Generate new server identity
	log.Printf("Generating new ECC key pair...")
	keyPair, err := auth.GenerateECCKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	encodedPrivateKey, err := auth.EncodePrivateKeyToBytes(keyPair.PrivateKeyECDSA)
	if err != nil {
		return err
	}
	encodedPublicKey, err := auth.EncodePublicKeyToBytes(keyPair.PublicKeyECDSA)
	if err != nil {
		return err
	}

	if len(encodedPrivateKey) > 0 && encodedPrivateKey[len(encodedPrivateKey)-1] == '\n' {
		encodedPrivateKey = encodedPrivateKey[:len(encodedPrivateKey)-1]
	}

	if len(encodedPublicKey) > 0 && encodedPublicKey[len(encodedPublicKey)-1] == '\n' {
		encodedPublicKey = encodedPublicKey[:len(encodedPublicKey)-1]
	}

	// Create DID
	did := "did:shade:" + hex.EncodeToString(crypto.FromECDSAPub(keyPair.PublicKeyECDSA))

	log.Printf("Registering new DID on blockchain: %s", did)
	walletPrivateKey, err := crypto.HexToECDSA(os.Getenv("SHADE_SERVER_WALLET_PRIVATE_KEY"))
	
	if err != nil {
		return fmt.Errorf("failed to parse wallet private key: %w", err)
	}

	err = registry.RegisterDID(walletPrivateKey, did, string(encodedPublicKey))
	if err != nil {
		return fmt.Errorf("failed to register DID: %w", err)
	}
	log.Printf("DID registered successfully")

	// Save keys to database
	serverKeys = &types.ServerKeys{
		DID:        did,
		PrivateKey: encodedPrivateKey,
		PublicKey:  encodedPublicKey,
	}

	return db.SaveServerKeys(ctx, serverKeys)
}

func loadContractABI() string {
	data, err := os.ReadFile("./blockchain/IdentityRegistry.json")
	if err != nil {
		log.Fatalf("Failed to read contract ABI file: %v", err)
	}

	var contract struct {
		ABI json.RawMessage `json:"abi"`
	}

	if err := json.Unmarshal(data, &contract); err != nil {
		log.Fatalf("Failed to parse contract JSON: %v", err)
	}

	return string(contract.ABI)
}
