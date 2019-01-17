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
	eks, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapCertification)
	require.NoError(t, err)
	msg := make([]byte, 32)
	rand.Read(msg)
	sig, err := eks.SignCertify(context.Background(), msg)
	require.NoError(t, err)

	//verify 1
	pub := eks.Public()
	err = pub.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)

	//verify 2
	cf := pub.CanonicalForm()
	pub2, err := EntityKeySchemeInstanceFor(cf)
	require.NoError(t, err)
	err = pub2.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)

	//verify 3
	cf2 := eks.SecretCanonicalForm()
	eks2, err := EntitySecretKeySchemeInstanceFor(cf2)
	require.NoError(t, err)
	pub3 := eks2.Public()
	err = pub3.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)
}

func TestEd25519Caps(t *testing.T) {
	eks, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapCertification)
	require.NoError(t, err)
	msg := make([]byte, 32)
	rand.Read(msg)
	sig, err := eks.SignCertify(context.Background(), msg)
	require.NoError(t, err)

	//verify 1
	pub := eks.Public()
	err = pub.VerifyCertify(context.Background(), msg, sig)
	require.NoError(t, err)

	//verify 2
	_, err = eks.SignAttestation(context.Background(), msg)
	require.Error(t, err)

	cf2 := eks.SecretCanonicalForm()

	eks2, err := EntitySecretKeySchemeInstanceFor(cf2)
	require.NoError(t, err)
	pub3 := eks2.Public()

	orig := eks.(*EntitySecretKey_Ed25519).SerdesForm.Public.Capabilities
	eks.(*EntitySecretKey_Ed25519).SerdesForm.Public.Capabilities = []int{int(CapSigning)}
	sig2, err := eks.SignMessage(context.Background(), msg)
	require.NoError(t, err)
	eks.(*EntitySecretKey_Ed25519).SerdesForm.Public.Capabilities = orig
	//The signature is correct but it must fail due to caps
	err = pub3.VerifyMessage(context.Background(), msg, sig2)
	require.Error(t, err)
}

func TestCurve25519(t *testing.T) {
	eks, err := NewEntityKeySchemeInstance(serdes.EntityCurve25519OID)
	require.NoError(t, err)

	pub := eks.Public()

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

	cf := eks.SecretCanonicalForm()
	ciphertext[0] ^= 0x80
	eks2, err := EntitySecretKeySchemeInstanceFor(cf)
	require.NoError(t, err)
	readback, err = eks2.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback)

	pub2, err := EntityKeySchemeInstanceFor(&cf.Public)
	require.NoError(t, err)
	ciphertext2, err := pub2.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)
	readback2, err := eks2.DecryptMessage(context.Background(), ciphertext2)
	require.NoError(t, err)
	require.EqualValues(t, msg, readback2)
}

func TestIBE_BLS12381(t *testing.T) {
	master, err := NewEntityKeySchemeInstance(serdes.EntityIBE_BLS12381_ParamsOID)
	require.NoError(t, err)

	params := master.Public()

	childpriv, err := master.GenerateChildSecretKey(context.Background(), []byte("foo"), true)
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

	readback3, err := master.DecryptMessageAsChild(context.Background(), ciphertext, []byte("foo"))
	require.NoError(t, err)
	require.EqualValues(t, msg, readback3)

	ciphertext[3] ^= 0x80
	readback2, err := childpriv.DecryptMessage(context.Background(), ciphertext)

	require.Error(t, err)
	require.Nil(t, readback2)
	ciphertext[3] ^= 0x80

	//now test serdes
	scf := master.SecretCanonicalForm()
	masterder, err := asn1.Marshal(*scf)
	require.NoError(t, err)
	readbackmaster := serdes.EntityKeyringEntry{}
	_, err = asn1.Unmarshal(masterder, &readbackmaster)
	require.NoError(t, err)
	master2, err := EntitySecretKeySchemeInstanceFor(&readbackmaster)
	require.NoError(t, err)
	childpriv2, err := master2.GenerateChildSecretKey(context.Background(), []byte("foo"), true)
	require.NoError(t, err)
	plaintext2, err := childpriv2.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext2)

	//Check child private key serdes works
	cf := childpriv2.SecretCanonicalForm()
	childer, err := asn1.Marshal(*cf)
	require.NoError(t, err)
	readbackchild := serdes.EntityKeyringEntry{}
	_, err = asn1.Unmarshal(childer, &readbackchild)
	require.NoError(t, err)
	childpriv3, err := EntitySecretKeySchemeInstanceFor(&readbackchild)
	require.NoError(t, err)
	plaintext3, err := childpriv3.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext3)

	//Check child public key serdes works
	pubeks := childpriv3.Public()
	cf2 := pubeks.CanonicalForm()
	pubder, err := asn1.Marshal(*cf2)
	require.NoError(t, err)
	readbackpub := serdes.EntityPublicKey{}
	_, err = asn1.Unmarshal(pubder, &readbackpub)
	require.NoError(t, err)
	pubeks2, err := EntityKeySchemeInstanceFor(&readbackpub)
	require.NoError(t, err)
	ciphertext2, err := pubeks2.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)
	plaintext4, err := childpriv.DecryptMessage(context.Background(), ciphertext2)
	require.NoError(t, err)
	require.EqualValues(t, msg, plaintext4)
}

func TestOAQUE(t *testing.T) {
	master, err := NewEntityKeySchemeInstance(serdes.EntityOAQUE_BLS12381_S20_ParamsOID)
	require.NoError(t, err)
	params := master.Public()

	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	k1, err := master.GenerateChildSecretKey(context.Background(), slots, true)
	require.NoError(t, err)

	k1pub := k1.Public()
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

func TestOAQUEKeySchemeFor(t *testing.T) {
	masterorig, err := NewEntityKeySchemeInstance(serdes.EntityOAQUE_BLS12381_S20_ParamsOID)
	require.NoError(t, err)
	mastercf := masterorig.SecretCanonicalForm()
	master, err := EntitySecretKeySchemeInstanceFor(mastercf)
	require.NoError(t, err)
	paramsorig := master.Public()
	paramscf := paramsorig.CanonicalForm()
	params, err := EntityKeySchemeInstanceFor(paramscf)
	require.NoError(t, err)
	_ = params

	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	k1orig, err := master.GenerateChildSecretKey(context.Background(), slots, true)
	require.NoError(t, err)
	k1cf := k1orig.SecretCanonicalForm()
	k1, err := EntitySecretKeySchemeInstanceFor(k1cf)
	require.NoError(t, err)

	k1puborig := k1.Public()
	k1pubcf := k1puborig.CanonicalForm()
	k1pub, err := EntityKeySchemeInstanceFor(k1pubcf)
	require.NoError(t, err)

	msg := make([]byte, 64)
	rand.Read(msg)

	ciphertext, err := k1pub.EncryptMessage(context.Background(), msg)
	require.NoError(t, err)

	rb1, err := k1.DecryptMessage(context.Background(), ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, msg, rb1)

	// ciphertext2, err := k1pub2.EncryptMessage(context.Background(), msg)
	// rb2, err := k1.DecryptMessage(context.Background(), ciphertext2)
	// require.NoError(t, err)
	// require.EqualValues(t, msg, rb2)
}

func TestOAQUEDelegation(t *testing.T) {
	master, err := NewEntityKeySchemeInstance(serdes.EntityOAQUE_BLS12381_S20_ParamsOID)
	require.NoError(t, err)
	//	params, err := master.Public()
	//	require.NoError(t, err)

	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	k1, err := master.GenerateChildSecretKey(context.Background(), slots, true)
	require.NoError(t, err)

	k1pub := k1.Public()
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
