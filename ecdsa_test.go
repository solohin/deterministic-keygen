package keyconverter_test

import (
	"encoding/hex"
	"testing"

	"github.com/solohin/keyconverter"
	"github.com/stretchr/testify/require"
)

const SAMPLE_KEY_HEX = "b7d5b73972baa52028d6a217ef945638b20f49c77e402e7729c3ee24a0d5f762"

func TestDecodeEcdsaHex(t *testing.T) {
	key, err := keyconverter.DecodeEcdsaHex(SAMPLE_KEY_HEX)
	require.NoError(t, err)
	bytes := key.D.Bytes()
	require.Equal(t, hex.EncodeToString(bytes[0:1]), "b7")
	require.Equal(t, hex.EncodeToString(bytes[len(bytes)-1:]), "62")
}
