package iapi

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/immesys/wave/serdes"
	"github.com/stretchr/testify/require"
)

func TestEd25519(t *testing.T) {
	eks, err := NewEntityKeyScheme(serdes.EntityEd25519OID)
	require.NoError(t, err)
	msg := make([]byte, 32)
	rand.Read(msg)
	sig, err := eks.SignCertify(context.Background(), msg)
	require.NoError(t, err)

	//verify 1
	pub, err := eks.Public()
	require.NoError(t, err)
	err = pub.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)

	//verify 2
	cf, err := pub.CanonicalForm(context.Background())
	require.NoError(t, err)
	pub2 := EntityKeySchemeFor(cf)
	err = pub2.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)

	//verify 3
	cf2, err := eks.SecretCanonicalForm(context.Background())
	require.NoError(t, err)
	eks2 := EntitySecretKeySchemeFor(cf2)
	pub3, err := eks2.Public()
	require.NoError(t, err)
	err = pub3.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)
}

func TestCurve25519(t *testing.T) {
	eks, err := NewEntityKeyScheme(serdes.EntityCurve25519OID)
	require.NoError(t, err)

	pub, err := eks.Public()
	require.NoError(t, err)

	msg := make([]byte, 32)
	rand.Read(msg)

	ciphertext, err := pub.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)
	readback, err := eks.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback)
	ciphertext[0] ^= 0x80
	_, err = eks.DecryptMessage(context.Background(), ciphertext)
	require.Error(t, err)

	cf, err := eks.SecretCanonicalForm(context.Background())
	require.NoError(t, err)
	ciphertext[0] ^= 0x80
	eks2 := EntitySecretKeySchemeFor(cf)
	readback, err = eks2.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback)

	pub2 := EntityKeySchemeFor(&cf.Public)

	ciphertext2, err := pub2.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)
	readback2, err := eks2.DecryptMessage(context.Background(), ciphertext2)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback2)
}

func TestIBE_BN256(t *testing.T) {
	master, err := NewEntityKeyScheme(serdes.EntityIBE_BN256_ParamsOID)
	require.NoError(t, err)

	params, err := master.Public()
	require.NoError(t, err)

	childpriv, err := master.GenerateChildSecretKey(context.Background(), []byte("foo"))
	require.NoError(t, err)

	childpub, err := params.GenerateChildKey(context.Background(), []byte("foo"))
	require.NoError(t, err)
	msg := make([]byte, 64)
	rand.Read(msg)

	ciphertext, err := childpub.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)

	readback, err := childpriv.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback)

	ciphertext[3] ^= 0x80
	readback2, err := childpriv.DecryptMessage(context.Background(), ciphertext)
	require.Error(t, err)
	require.Nil(t, readback2)
}
