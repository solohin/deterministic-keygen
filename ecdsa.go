package keyconverter

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
)

func DecodeEcdsaHex(keyHex string) (*ecdsa.PrivateKey, error) {
	if keyHex[:2] == "0x" {
		keyHex = keyHex[2:]
	}
	return crypto.HexToECDSA(keyHex)
}
