package blockchain

import (
	_ "bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	_ "reflect"
	_ "shade-server/auth"
	_ "shade-server/types"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type IdentityRegistry struct {
	client  *ethclient.Client
	address common.Address
	abi     abi.ABI
}

func NewIdentityRegistry(rpcURL, contractAddress string, contractABI string) (*IdentityRegistry, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %v", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %v", err)
	}

	return &IdentityRegistry{
		client:  client,
		address: common.HexToAddress(contractAddress),
		abi:     parsedABI,
	}, nil
}

func (ir *IdentityRegistry) RegisterDID(privateKey *ecdsa.PrivateKey, did string, publicKey string) error {
	auth, err := ir.getTransactOpts(privateKey)
	if err != nil {
		return err
	}

	data, err := ir.abi.Pack("registerDID", did, publicKey)
	if err != nil {
		return fmt.Errorf("failed to pack data: %v", err)
	}

	// Estimate gas specifically for this transaction
	estimatedGas, err := ir.client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: auth.From,
		To:   &ir.address,
		Data: data,
	})
	if err != nil {
		log.Printf("Warning: Gas estimation failed: %v", err)
		// If estimation fails, use a higher default value
		estimatedGas = uint64(500000)
	}

	// Add 20% buffer to estimated gas
	auth.GasLimit = estimatedGas + (estimatedGas * 20 / 100)

	log.Printf("Registering DID with Gas Limit: %d, Gas Price: %s wei",
		auth.GasLimit, auth.GasPrice.String())

	tx := types.NewTransaction(
		auth.Nonce.Uint64(),
		ir.address,
		auth.Value,
		auth.GasLimit,
		auth.GasPrice,
		data,
	)

	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	err = ir.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	receipt, err := bind.WaitMined(context.Background(), ir.client, signedTx)
	if err != nil {
		return fmt.Errorf("failed to wait for transaction to be mined: %v", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("transaction failed")
	}

	return nil
}

func (ir *IdentityRegistry) IsValidDID(did string) (bool, error) {
	data, err := ir.abi.Pack("isValidDID", did)
	if err != nil {
		return false, fmt.Errorf("failed to pack data: %v", err)
	}

	result, err := ir.client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &ir.address,
		Data: data,
	}, nil)
	if err != nil {
		return false, err
	}

	var isValid bool
	err = ir.abi.UnpackIntoInterface(&isValid, "isValidDID", result)
	return isValid, err
}

func (ir *IdentityRegistry) getTransactOpts(privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	chainID, err := ir.client.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, err
	}

	nonce, err := ir.client.PendingNonceAt(context.Background(), crypto.PubkeyToAddress(privateKey.PublicKey))
	if err != nil {
		return nil, err
	}

	data, err := ir.abi.Pack("registerDID", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to pack data: %v", err)
	}

	// Increase gas limit significantly
	estimatedGas, err := ir.client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: crypto.PubkeyToAddress(privateKey.PublicKey),
		To:   &ir.address,
		Data: data,
	})
	if err != nil {
		log.Printf("Warning: Failed to estimate gas, using default higher value: %v", err)
		estimatedGas = uint64(500000) // Higher default value
	}

	// Add 20% buffer to estimated gas
	gasLimit := estimatedGas + (estimatedGas * 20 / 100)

	// Get suggested gas price and add a buffer for faster confirmation
	gasPrice, err := ir.client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}
	// Increase gas price by 20% for faster confirmation
	adjustedGasPrice := new(big.Int).Mul(gasPrice, big.NewInt(120))
	adjustedGasPrice = adjustedGasPrice.Div(adjustedGasPrice, big.NewInt(100))

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = gasLimit
	auth.GasPrice = adjustedGasPrice

	log.Printf("Transaction settings - Gas Limit: %d, Gas Price: %s wei",
		auth.GasLimit, auth.GasPrice.String())

	return auth, nil
}

// Add this struct to match the Solidity struct if not already present
type DIDDocument struct {
	DID       string   `json:"did"`
	PublicKey string   `json:"publicKey"`
	Timestamp *big.Int `json:"timestamp"`
	Active    bool     `json:"active"`
}

// Add this new function to your IdentityRegistry struct
func (ir *IdentityRegistry) GetDIDDocument(did string) (*DIDDocument, error) {
	log.Printf("Fetching DID Document for DID: %s", did)

	data, err := ir.abi.Pack("getDIDDocument", did)
	if err != nil {
		return nil, fmt.Errorf("failed to pack data for getDIDDocument: %v", err)
	}

	result, err := ir.client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &ir.address,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call getDIDDocument: %v", err)
	}

	values, err := ir.abi.Methods["getDIDDocument"].Outputs.Unpack(result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DID document: %v", err)
	}

	// The result is already a struct, so we can type assert directly to our struct
	structValue := values[0].(struct {
		Did       string   `json:"did"`
		PublicKey string   `json:"publicKey"`
		Timestamp *big.Int `json:"timestamp"`
		Active    bool     `json:"active"`
	})
	
	didDoc := &DIDDocument{
		DID:       structValue.Did,
		PublicKey: structValue.PublicKey,
		Timestamp: structValue.Timestamp,
		Active:    structValue.Active,
	}

	return didDoc, nil
}
