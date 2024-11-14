package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// generate a safe prime (p) -> p = 2q + 1, where q is also prime
func GenerateSafePrime(bits int) (*big.Int, error) {
	for {
		q, err := rand.Prime(rand.Reader, bits-1)
		if err != nil {
			return nil, err
		}

		// p = 2q + 1
		p := new(big.Int).Mul(q, big.NewInt(2))
		p = p.Add(p, big.NewInt(1))

		// miller-rabin test (30 rounds)
		if p.ProbablyPrime(30) {
			return p, nil
		}
	}
}

func FindGenerator(p *big.Int) (*big.Int, error) {
	q := new(big.Int).Sub(p, big.NewInt(1))
	q = q.Div(q, big.NewInt(2))
	pMinusTwo := new(big.Int).Sub(p, big.NewInt(2))

	for g := big.NewInt(2); g.Cmp(pMinusTwo) <= 0; g.Add(g, big.NewInt(1)) {
		temp1 := new(big.Int).Exp(g, q, p)
		temp2 := new(big.Int).Exp(g, big.NewInt(2), p)

		if temp1.Cmp(big.NewInt(1)) != 0 && temp2.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}

	return nil, fmt.Errorf("no suitable generator found")
}

func GenerateDHParameters(bits int) (*DHParams, error) {
	counter := 0

	prime, err := GenerateSafePrime(bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime: %v", err)
	}

	generator, err := FindGenerator(prime)

	for err != nil && counter < 100 {
		counter += 1
		prime, err = GenerateSafePrime(bits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate prime: %v", err)
		}

		generator, err = FindGenerator(prime)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to find field generator: %v", err)
	}

	privateKey, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// y = g^a mod p
	publicKey := new(big.Int).Exp(generator, privateKey, prime)

	return &DHParams{
		Prime:      prime,
		Generator:  generator,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func (dh *DHParams) ComputeSharedSecret(otherPublicKey *big.Int) error {
	if otherPublicKey == nil {
		return fmt.Errorf("invalid public key")
	}

	dh.SharedSecret = new(big.Int).Exp(otherPublicKey, dh.PrivateKey, dh.Prime)

	return nil
}

func (dh *DHParams) DeriveKey() ([]byte, error) {
	if dh.SharedSecret == nil {
		return nil, fmt.Errorf("shared secret not computed")
	}

	hash := sha256.New
	salt := make([]byte, hash().Size())
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	info := []byte("DID Auth Encryption Key")
	hkdf := hkdf.New(hash, dh.SharedSecret.Bytes(), salt, info)

	key := make([]byte, 32)
	_, err = io.ReadFull(hkdf, key)

	return key, err
}

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generate a new ECC key pair for DID
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// signs a challenge with the DID private key
func SignChallenge(privateKey *ecdsa.PrivateKey, challenge []byte) ([]byte, error) {
	hash := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

// verify the challenge signature
func VerifySignature(publicKey *ecdsa.PublicKey, challenge []byte, signature []byte) bool {
	hash := sha256.Sum256(challenge)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(publicKey, hash[:], r, s)
}
