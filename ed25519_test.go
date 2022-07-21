package keyconverter_test

import (
	"encoding/hex"
	"testing"

	"github.com/solohin/keyconverter"
	"github.com/stretchr/testify/require"
)

func TestEd25519FromEcdsa(t *testing.T) {
	ecdsaKey, err := keyconverter.DecodeEcdsaHex(SAMPLE_KEY_HEX)
	require.NoError(t, err)

	ed25519Key := keyconverter.CovertEcdsaToEd25519(ecdsaKey)
	_ = ed25519Key

	ed25519KeyString := hex.EncodeToString(ed25519Key)
	require.Equal(t, SAMPLE_KEY_HEX, ed25519KeyString[0:64])
}

func TestDeriveNextEd25519(t *testing.T) {
	ecdsaKey, err := keyconverter.DecodeEcdsaHex(SAMPLE_KEY_HEX)
	require.NoError(t, err)

	ed25519Key := keyconverter.CovertEcdsaToEd25519(ecdsaKey)

	nextEd25519Key, err := keyconverter.DeriveNextEd25519(ed25519Key)
	require.NoError(t, err)

	require.Equal(t, hex.EncodeToString(nextEd25519Key), "f764aca4da44293afcc6ac1784de1d61f0d662afc3784da26f59324e5f5c2a802c3883f84d7b4f1a834317735d45955510f2e3ca68504b222cbb15aea27fa691")
}
