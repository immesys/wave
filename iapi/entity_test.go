package iapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateEntity(t *testing.T) {
	R, err := NewEntity(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	//fmt.Printf("Public part: %x\n", R.PublicDER)
	//fmt.Printf("Secret part: %x\n", R.SecretDER)
	readback, err := ParseEntity(context.Background(), &PParseEntity{
		DER: R.PublicDER,
	})
	require.NoError(t, err)

	require.NotNil(t, readback.Entity)
	require.NotNil(t, readback.Entity.VerifyingKey)
}

func TestCreateEntityAndParseSecrets(t *testing.T) {
	R, err := NewEntity(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	es, err := ParseEntitySecrets(context.Background(), &PParseEntitySecrets{
		DER: R.SecretDER,
	})
	require.NoError(t, err)
	require.NotNil(t, es.EntitySecrets)
}

func TestCreateEntityAndParseSecretsWithPassphrase(t *testing.T) {
	R, err := NewEntity(context.Background(), &PNewEntity{
		Passphrase: String("hello"),
	})
	require.NoError(t, err)
	es, err := ParseEntitySecrets(context.Background(), &PParseEntitySecrets{
		DER:        R.SecretDER,
		Passphrase: String("hello"),
	})
	require.NoError(t, err)
	require.NotNil(t, es.EntitySecrets)
}

func TestCreateEntityAndParseSecretsWithWrongPassphrase(t *testing.T) {
	R, err := NewEntity(context.Background(), &PNewEntity{
		Passphrase: String("hello"),
	})
	require.NoError(t, err)
	es, err := ParseEntitySecrets(context.Background(), &PParseEntitySecrets{
		DER:        R.SecretDER,
		Passphrase: String("nothello"),
	})
	require.Error(t, err)
	require.Nil(t, es)
}
