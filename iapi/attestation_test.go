package iapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicAttestation(t *testing.T) {
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	pol, err := NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := NewPlaintextBodyScheme()
	rv, err := CreateAttestation(context.Background(), &PCreateAttestation{
		Policy:            pol,
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
	kpdc.AddEntity(source.EntitySecrets.Entity)

	readback, err := ParseAttestation(context.Background(), &PParseAttestation{
		DER:               rv.DER,
		DecryptionContext: kpdc,
	})
	require.NoError(t, err)
	//spew.Dump(readback)
	_ = readback
}
func TestBasicAttestationDER(t *testing.T) {
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	pol, err := NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := NewPlaintextBodyScheme()
	rv, err := CreateAttestation(context.Background(), &PCreateAttestation{
		Policy:            pol,
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
	kpdc.AddEntity(source.EntitySecrets.Entity)
	readback, err := ParseAttestation(context.Background(), &PParseAttestation{
		DER:               rv.DER,
		DecryptionContext: kpdc,
	})
	require.NoError(t, err)
	rbder, err := readback.Attestation.DER()
	require.NoError(t, err)
	require.EqualValues(t, rv.DER, rbder)
}

func oneHopAttestation(t *testing.T, delegatedOnly bool) {
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
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
	kpdc.AddEntity(source.Entity)
	kpdc.AddEntitySecret(dst.EntitySecrets, delegatedOnly)
	readback, err := ParseAttestation(context.Background(), &PParseAttestation{
		DER:               rv.DER,
		DecryptionContext: kpdc,
	})
	_ = readback
	require.NoError(t, err)
}
func TestWR1DirectAttestation(t *testing.T) {
	oneHopAttestation(t, false)
}

func TestWR1IndirectAttestation(t *testing.T) {
	oneHopAttestation(t, true)
}
