package iapi

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestBasicAttestation(t *testing.T) {
	source, err := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	dst, err := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	pol, err := NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := NewPlaintextBodyScheme()
	rv, err := CreateAttestation(context.Background(), &PCreateAttestation{
		Policy:            pol,
		HashScheme:        &HashScheme_Sha3_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          source.EntitySecrets,
		Subject:           dst.EntitySecrets.Entity,
	})
	require.NoError(t, err)

	readback, err := DecodeAttestation(context.Background(), &PDecodeAttestation{
		DER: rv.DER,
	})
	require.NoError(t, err)
	spew.Dump(readback)
}
