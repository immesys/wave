package csroaque

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

const attrMaxSize, userMaxSize = 10, 10

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
}

func encryptHelper(t *testing.T, params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) CiphertextList {
	ciphertext, err := Encrypt(params, attrs, revoc, message)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey *MasterKey, attrs oaque.AttributeList, userNum int, newUser int) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGen(params, masterkey, attrs, userNum, newUser)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func qualifyHelper(t *testing.T, params *Params, key *PrivateKey, attrs oaque.AttributeList, lEnd int, rEnd int) *PrivateKey {
	key, err := QualifyKey(params, key, attrs, lEnd, rEnd)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, params *Params, key *PrivateKey, ciphertext CiphertextList, message *bn256.GT) {
	decrypted := Decrypt(params, key, ciphertext)
	if decrypted == nil || !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func decryptAndCheckHelper2(t *testing.T, params *Params, key *PrivateKey, ciphertext CiphertextList, message *bn256.GT) {
	decrypted := Decrypt(params, key, ciphertext)
	if decrypted == nil || !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		return
	}
	t.Fatal("Original and decrypted messages are the same")
}

func attributeFromMasterHelper(t *testing.T, attrs oaque.AttributeList, revoc RevocationList) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, revoc, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, attrs, 0, userMaxSize)

	decryptAndCheckHelper(t, params, key, ciphertext, message)
}

func TestSingleAttribute(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{0: big.NewInt(0)}, RevocationList{0: 0})
}

func TestSingleSparseAttribute(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{1: big.NewInt(0)}, RevocationList{0: 0})
}

func TestMultipleSparseAttributes(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{1: big.NewInt(0), attrMaxSize - 1: big.NewInt(123)}, RevocationList{0: 0})
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{1, 2, 4}
	revoc2 := RevocationList{1, 2, 3}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 0, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, *key1.lEnd, *key1.lEnd+2)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}
