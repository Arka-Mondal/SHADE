/*
 * Author: Arka Mondal
 * Date: 16th November, 2024
 */

package auth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
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
