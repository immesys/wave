package iapi

import (
	"context"
	"testing"

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
		AttesterLocation:  NewLocationSchemeInstanceURL("test", 1),
		Subject:           dst.EntitySecrets.Entity,
		SubjectLocation:   NewLocationSchemeInstanceURL("test", 1),
	})
	require.NoError(t, err)

	readback, err := ParseAttestation(context.Background(), &PParseAttestation{
		DER: rv.DER,
	})
	require.NoError(t, err)
	//spew.Dump(readback)
	_ = readback
}
