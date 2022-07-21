package keyconverter_test

import (
	"testing"

	"github.com/solohin/keyconverter"
	"github.com/stretchr/testify/require"
)

func TestDeriveBestYggdrasilKeyFromEd25519(t *testing.T) {
	ecdsaKey, err := keyconverter.DecodeEcdsaHex(SAMPLE_KEY_HEX)
	require.NoError(t, err)

	ed25519Key := keyconverter.CovertEcdsaToEd25519(ecdsaKey)

	yggKeySet, err := keyconverter.DeriveBestYggdrasilKeyFromEd25519(ed25519Key)
	require.NoError(t, err)

	ip := yggKeySet.GetIP()
	require.Equal(t, "20d:c44b:336a:2205:fb23:97a7:72b7:ebd4", ip)
}
