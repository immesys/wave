package hibe

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ucbrise/starwave/crypto/cryptutils"
	"vuvuzela.io/crypto/bn256"
)

var ID = []string{"a", "b", "c"}
var Message = bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))

func IDToInts(id []string) []*big.Int {
	ints := make([]*big.Int, len(id))
	for i, component := range id {
		ints[i] = cryptutils.HashToZp([]byte(component))
	}
	return ints
}

func TestHashID(t *testing.T) {
	idints := IDToInts(ID)
	for _, idint := range idints {
		if idint.Cmp(bn256.Order) != -1 || idint.Cmp(big.NewInt(0)) != 1 {
			t.Fatal("ID components are not in Zp*")
		}
	}
}

func TestTopLevelWithMarshalling(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	parambytes := params.Marshal()
	params = new(Params)
	_, ok := params.Unmarshal(parambytes)
	if !ok {
		t.Fatal("Could not unmarshal Params")
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext, err := Encrypt(rand.Reader, params, IDToInts(ID[:1]), message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertextbytes := ciphertext.Marshal()
	ciphertext = new(Ciphertext)
	_, ok = ciphertext.Unmarshal(ciphertextbytes)
	if !ok {
		t.Fatal("Could not unmarshal Ciphertext")
	}

	// Generate key for the top level
	toplevelkey, err := KeyGen(rand.Reader, params, key, IDToInts(ID[:1]))
	if err != nil {
		t.Fatal(err)
	}

	toplevelkeybytes := toplevelkey.Marshal()
	toplevelkey = new(PrivateKey)
	_, ok = toplevelkey.Unmarshal(toplevelkeybytes)
	if !ok {
		t.Fatal("Could not unmarshal private key")
	}

	if toplevelkey.DepthLeft() != 9 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(toplevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}
