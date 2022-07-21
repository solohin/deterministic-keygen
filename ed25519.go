package deterministickeygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func CovertEcdsaToEd25519(ecdsaPk *ecdsa.PrivateKey) ed25519.PrivateKey {
	keyBytes := ecdsaPk.D.Bytes()
	key := ed25519.NewKeyFromSeed(keyBytes)
	return key
}

func DeriveNextEd25519(privateKey ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	keyBytes := privateKey[:]
	keyHash := sha256.Sum256(keyBytes)

	hash := sha256.New
	salt := keyHash[:]

	hkdf := hkdf.New(hash, keyBytes, salt, nil)

	seed := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, seed); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
