package lukpabe

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
}

func encryptHelper(t *testing.T, params *Params, attrs AttributeSet, message *bn256.GT) *Ciphertext {
	ciphertext, err := Encrypt(nil, params, attrs, message)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey MasterKey, tree AccessNode) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGen(rand.Reader, params, masterkey, tree)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, key *PrivateKey, ciphertext *Ciphertext, message *bn256.GT, fail bool) {
	decrypted, _ := Decrypt(key, ciphertext, nil)
	if fail {
		if decrypted != nil {
			t.Fatal("Decryption returned a message but should have failed")
		}
	} else if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func attributeFromMasterHelper(t *testing.T, attrs AttributeSet, tree AccessNode, fail bool) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, tree)

	decryptAndCheckHelper(t, key, ciphertext, message, fail)
}

func TestSingleAttribute(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13)}
	tree := &AccessLeaf{
		Attr: big.NewInt(13),
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestORAccessTree(t *testing.T) {
	attrs := AttributeSet{big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 1,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestANDAccessTree(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13), big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestAccessTreeFail(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13), big.NewInt(17)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, true)
}

func TestDecryptSpecific(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13), big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}

	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, tree)

	decrypted := DecryptSpecific(params, key, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func NewRandomMessage(random io.Reader) (*bn256.GT, error) {
	_, g1, err := bn256.RandomG1(random)
	if err != nil {
		return nil, err
	}
	_, g2, err := bn256.RandomG2(random)
	if err != nil {
		return nil, err
	}
	return bn256.Pair(g1, g2), nil
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func EncryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, _, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeSet, numAttributes)
		for i := 0; i != numAttributes; i++ {
			attrs[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StartTimer()
		_, err = Encrypt(nil, params, attrs, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt_5(b *testing.B) {
	EncryptBenchmarkHelper(b, 5)
}

func BenchmarkEncrypt_10(b *testing.B) {
	EncryptBenchmarkHelper(b, 10)
}

func BenchmarkEncrypt_15(b *testing.B) {
	EncryptBenchmarkHelper(b, 15)
}

func BenchmarkEncrypt_20(b *testing.B) {
	EncryptBenchmarkHelper(b, 20)
}

func DecryptBenchmarkHelper(b *testing.B, numAttributes int, fast bool) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	tree := &AccessGate{
		Thresh: numAttributes,
		Inputs: make([]AccessNode, numAttributes),
	}

	for i := range tree.Inputs {
		tree.Inputs[i] = new(AccessLeaf)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeSet, numAttributes)
		for i := 0; i != numAttributes; i++ {
			attrs[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
			tree.Inputs[i].AsLeaf().Attr = attrs[i]
		}

		key, err := KeyGen(rand.Reader, params, master, tree)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(nil, params, attrs, message)
		if err != nil {
			b.Fatal(err)
		}

		var decrypted *bn256.GT
		if fast {
			b.StartTimer()
			decrypted = DecryptSpecific(params, key, ciphertext)
			b.StopTimer()
		} else {
			b.StartTimer()
			decrypted, _ = Decrypt(key, ciphertext, tree)
			b.StopTimer()
		}

		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecrypt_5(b *testing.B) {
	DecryptBenchmarkHelper(b, 5, false)
}

func BenchmarkDecrypt_10(b *testing.B) {
	DecryptBenchmarkHelper(b, 10, false)
}

func BenchmarkDecrypt_15(b *testing.B) {
	DecryptBenchmarkHelper(b, 15, false)
}

func BenchmarkDecrypt_20(b *testing.B) {
	DecryptBenchmarkHelper(b, 20, false)
}

func BenchmarkDecryptSpecific_5(b *testing.B) {
	DecryptBenchmarkHelper(b, 5, true)
}

func BenchmarkDecryptSpecific_10(b *testing.B) {
	DecryptBenchmarkHelper(b, 10, true)
}

func BenchmarkDecryptSpecific_15(b *testing.B) {
	DecryptBenchmarkHelper(b, 15, true)
}

func BenchmarkDecryptSpecific_20(b *testing.B) {
	DecryptBenchmarkHelper(b, 20, true)
}
