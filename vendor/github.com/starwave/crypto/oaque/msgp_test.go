package oaque

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/tinylib/msgp/msgp"
)

//go:generate msgp -o=msgp_gen_test.go -marshal=false -tests=false

type TestMessage struct {
	Params          *Params
	MasterKey       *MasterKey
	PrivateKey      *PrivateKey
	Signature       *Signature
	SignatureParams *SignatureParams
	Ciphertext      *Ciphertext
}

func TestMsgpEncodings(t *testing.T) {
	tm := TestMessage{}

	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}
	sigparams, err := SignatureSetup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tm.Params = params
	tm.SignatureParams = sigparams
	tm.MasterKey = key

	// Come up with a message to encrypt
	message := NewMessage()
	smessage, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Encrypt a message under the top level public key
	ciphertext, err := Encrypt(nil, params, attrs1, message)
	if err != nil {
		t.Fatal(err)
	}
	tm.Ciphertext = ciphertext

	privkey, err := KeyGen(nil, params, key, attrs1)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := Sign(nil, params, sigparams, privkey, smessage)
	if err != nil {
		t.Fatal(err)
	}
	tm.Signature = signature
	tm.PrivateKey = privkey

	buf := new(bytes.Buffer)
	err = msgp.Encode(buf, &tm)
	if err != nil {
		t.Fatal(err)
	}
	readBack := TestMessage{}
	err = msgp.Decode(buf, &readBack)
	if err != nil {
		t.Fatal(err)
	}

	// Now, check whether the unmarshalled elements still work

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(tm.PrivateKey, tm.Ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}

	// Key generation from the master key
	privkey2, err := KeyGen(nil, tm.Params, tm.MasterKey, attrs1)
	if err != nil {
		t.Fatal(err)
	}
	decrypted = Decrypt(privkey2, tm.Ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}

	// Verify the signature
	correct := Verify(tm.Params, tm.SignatureParams, attrs1, tm.Signature, smessage)
	if !correct {
		t.Fatal("Signature was not successfully verified")
	}
}
