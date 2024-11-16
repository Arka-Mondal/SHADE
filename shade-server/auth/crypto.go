/*
 * Author: Arka Mondal
 * Date: 16th November, 2024
 */

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
	"shade-server/types"

	"golang.org/x/crypto/hkdf"
)

/** GenerateECCKeyPair - generate a new ECC key pair
 *
 * @return: Public-Private Key Pair
 */
func GenerateECCKeyPair() (*types.KeyPairECDSA, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &types.KeyPairECDSA{
		PrivateKeyECDSA: privateKeyECDSA,
		PublicKeyECDSA:  &privateKeyECDSA.PublicKey,
	}, nil
}

/** ECDHComputeSharedSecret - Computes the Shared Secret from the ECC-pubic-private key pair
 *
 * @param: privateKey - own private key
 * @param: otherPublicKey - other's public key
 *
 * @return: ECDH Parameters
 */
func ECDHComputeSharedSecret(privateKey *ecdsa.PrivateKey, otherPublicKey *ecdsa.PublicKey) (*types.ECDHSharedSecret, error) {
	privateKeyECDH, err := privateKey.ECDH()
	if err != nil {
		return nil, err
	}
	publicKeyECDH, err := otherPublicKey.ECDH()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := privateKeyECDH.ECDH(publicKeyECDH)
	if err != nil {
		return nil, err
	}

	return &types.ECDHSharedSecret{
		SharedSecret: sharedSecret,
	}, nil
}

/** DeriveKey - Computes the encryption key from the both identity and ephemeral shared secrets
 *
 * @param: id_ecdh - identity shared secret
 * @param: eph_ecdh - ephemeral shared secret
 * @param: salt: - nil : use new salt else use given salt
 *
 * @return: key, salt
 */
func DeriveKey(id_ecdh *types.ECDHSharedSecret, eph_ecdh *types.ECDHSharedSecret, salt []byte) ([]byte, []byte, error) {
	if id_ecdh.SharedSecret == nil || eph_ecdh.SharedSecret == nil {
		return nil, nil, fmt.Errorf("shared secret not computed")
	}

	hash := sha256.New

	// generate a salt
	if salt == nil {
		salt = make([]byte, hash().Size())
		_, err := rand.Read(salt)
		if err != nil {
			return nil, nil, err
		}
	}

	combinedSecret := append(id_ecdh.SharedSecret, eph_ecdh.SharedSecret...)

	// derive the encryption key from the Combined shared secret
	info := []byte("Authentication Encryption Key")
	hkdf := hkdf.New(hash, combinedSecret, salt, info)

	// generate the key
	key := make([]byte, hash().Size())
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

/** Encrypt - Encrypts plaintext with given key
 *
 * @param: key - encryption key
 * @param: plaintext - plaintext to be encrypted
 *
 * @return: encrypted text with used nonce
 */
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) // selects AES-256 as key is 32-bits
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

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertextWithNonce := append(nonce, ciphertext...)

	return ciphertextWithNonce, nil
}

/** Decrypt - Decrypts encrypted text with given key
 *
 * @param: key - encryption key
 * @param: plaintext - encrypted text to be decrypted
 *
 * @return: decrypted text
 */
func Decrypt(key []byte, ciphertextWithNonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertextWithNonce) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertextWithNonce[:gcm.NonceSize()], ciphertextWithNonce[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

/** SignChallenge - signs a challenge with the ECC private key
 *
 * @param: privateKey - own private key
 * @param: challenge - challenge to be signed
 *
 * @return: signature
 */
func SignChallenge(privateKey *ecdsa.PrivateKey, challenge []byte) ([]byte, error) {

	hash := sha256.Sum256(challenge)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

/** VerifySignature - verify the challenge signature
 *
 * @param: privateKey - signer's public key
 * @param: challenge - signed challenge
 * @param: signature - signature
 *
 * @return: validity of the signature
 */
func VerifySignature(publicKey *ecdsa.PublicKey, challenge []byte, signature []byte) (bool, error) {

	curve := publicKey.Curve
	byteSize := (curve.Params().BitSize + 7) / 8

	if len(signature) != byteSize<<1 {
		return false, fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:byteSize])
	s := new(big.Int).SetBytes(signature[byteSize:])

	hash := sha256.Sum256(challenge)

	return ecdsa.Verify(publicKey, hash[:], r, s), nil
}
