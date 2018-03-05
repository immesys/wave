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

func TestWR1DirectAttestation(t *testing.T) {
	source, err := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	dst, err := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	pol, err := NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := &WR1BodyScheme{}
	rv, err := CreateAttestation(context.Background(), &PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          source.EntitySecrets,
		AttesterLocation:  NewLocationSchemeInstanceURL("test", 1),
		Subject:           dst.EntitySecrets.Entity,
		SubjectLocation:   NewLocationSchemeInstanceURL("test", 1),
	})
	require.NoError(t, err)

	kpdc := NewKeyPoolDecryptionContext()
	kpdc.AddEntitySecret(dst.EntitySecrets)

	readback, err := ParseAttestation(context.Background(), &PParseAttestation{
		DER:               rv.DER,
		DecryptionContext: kpdc,
	})
	require.NoError(t, err)
	spew.Dump(readback)
}
