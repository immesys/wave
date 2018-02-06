package iapi

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/immesys/asn1"

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
	ciphertext[3] ^= 0x80

	//now test serdes
	scf, err := master.SecretCanonicalForm(context.Background())
	require.NoError(t, err)
	masterder, err := asn1.Marshal(*scf)
	require.NoError(t, err)
	readbackmaster := serdes.EntityKeyringEntry{}
	_, err = asn1.Unmarshal(masterder, &readbackmaster)
	require.NoError(t, err)
	master2 := EntitySecretKeySchemeFor(&readbackmaster)
	childpriv2, err := master2.GenerateChildSecretKey(context.Background(), []byte("foo"))
	require.NoError(t, err)
	plaintext2, err := childpriv2.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext2)

	//Check child private key serdes works
	cf, err := childpriv2.SecretCanonicalForm(context.Background())
	require.NoError(t, err)
	childer, err := asn1.Marshal(*cf)
	require.NoError(t, err)
	readbackchild := serdes.EntityKeyringEntry{}
	_, err = asn1.Unmarshal(childer, &readbackchild)
	require.NoError(t, err)
	childpriv3 := EntitySecretKeySchemeFor(&readbackchild)
	plaintext3, err := childpriv3.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext3)

	//Check child public key serdes works
	pubeks, err := childpriv3.Public()
	require.NoError(t, err)
	cf2, err := pubeks.CanonicalForm(context.Background())
	require.NoError(t, err)
	pubder, err := asn1.Marshal(*cf2)
	require.NoError(t, err)
	readbackpub := serdes.EntityPublicKey{}
	_, err = asn1.Unmarshal(pubder, &readbackpub)
	require.NoError(t, err)
	pubeks2 := EntityKeySchemeFor(&readbackpub)
	ciphertext2, err := pubeks2.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)
	plaintext4, err := childpriv.DecryptMessage(context.Background(), ciphertext2)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext4)
}

func TestOAQUE(t *testing.T) {
	master, err := NewEntityKeyScheme(serdes.EntityOAQUE_BN256_S20_ParamsOID)
	require.NoError(t, err)
	params, err := master.Public()
	require.NoError(t, err)

	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	k1, err := master.GenerateChildSecretKey(context.Background(), slots)
	require.NoError(t, err)

	k1pub, err := k1.Public()
	require.NoError(t, err)
	k1pub2, err := params.GenerateChildKey(context.Background(), slots)

	msg := make([]byte, 64)
	rand.Read(msg)

	ciphertext, err := k1pub.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)

	rb1, err := k1.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, rb1)

	ciphertext2, err := k1pub2.EncryptMessage(context.Background(), msg)
	rb2, err := k1.DecryptMessage(context.Background(), ciphertext2)
	require.NoError(t, err)
	require.EqualValues(t, msg, rb2)
}

func TestOAQUEDelegation(t *testing.T) {
	master, err := NewEntityKeyScheme(serdes.EntityOAQUE_BN256_S20_ParamsOID)
	require.NoError(t, err)
	//	params, err := master.Public()
	//	require.NoError(t, err)

	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	k1, err := master.GenerateChildSecretKey(context.Background(), slots)
	require.NoError(t, err)

	k1pub, err := k1.Public()
	require.NoError(t, err)
	slots[1] = []byte("bar")
	k2pub, err := k1pub.GenerateChildKey(context.Background(), slots)
	require.NoError(t, err)

	msg := make([]byte, 64)
	rand.Read(msg)

	ciphertext, err := k2pub.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)

	_, err = k1.DecryptMessage(context.Background(), ciphertext)
	require.Error(t, err)

	rb, err := k1.DecryptMessageAsChild(context.Background(), ciphertext, slots)
	require.NoError(t, err)
	require.EqualValues(t, msg, rb)
}
