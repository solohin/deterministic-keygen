package deterministickeygen

import (
	"crypto/ed25519"
	"net"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type KeySetYggdrasil struct {
	Priv ed25519.PrivateKey
}

func (ks *KeySetYggdrasil) GetPublicKey() ed25519.PublicKey {
	return ks.Priv.Public().(ed25519.PublicKey)
}

func (ks *KeySetYggdrasil) GetIP() string {
	addr := address.AddrForKey(ks.GetPublicKey())
	return net.IP(addr[:]).String()
}

func DeriveBestYggdrasilKeyFromEd25519(originalPK ed25519.PrivateKey) (*KeySetYggdrasil, error) {
	var currentBest ed25519.PrivateKey
	var err error
	newPrivateKey := originalPK

	for i := 0; i < 20000; i++ {
		newPrivateKey, err = DeriveNextEd25519(newPrivateKey)
		if err != nil {
			return nil, err
		}

		if currentBest == nil || isBetter(
			currentBest.Public().(ed25519.PublicKey),
			newPrivateKey.Public().(ed25519.PublicKey),
		) {
			currentBest = newPrivateKey
		}
	}

	return &KeySetYggdrasil{currentBest}, nil
}

// is hegher or lower better? idk
// here lower is better https://github.com/yggdrasil-network/yggdrasil-go/blob/41b4bf69cfa7b0a2e0f7904867e49160f9283cea/cmd/genkeys/main.go#L62
func isBetter(oldPub, newPub ed25519.PublicKey) bool {
	for idx := range oldPub {
		if newPub[idx] < oldPub[idx] {
			return true
		}
		if newPub[idx] > oldPub[idx] {
			break
		}
	}
	return false
}
