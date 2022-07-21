package deterministickeygen_test

import (
	"testing"

	deterministickeygen "github.com/solohin/deterministic-keygen"
	"github.com/stretchr/testify/require"
)

func TestDeriveBestYggdrasilKeyFromEd25519(t *testing.T) {
	ecdsaKey, err := deterministickeygen.DecodeEcdsaHex(SAMPLE_KEY_HEX)
	require.NoError(t, err)

	ed25519Key := deterministickeygen.CovertEcdsaToEd25519(ecdsaKey)

	yggKeySet, err := deterministickeygen.DeriveBestYggdrasilKeyFromEd25519(ed25519Key)
	require.NoError(t, err)

	ip := yggKeySet.GetIP()
	require.Equal(t, "20d:c44b:336a:2205:fb23:97a7:72b7:ebd4", ip)
}
