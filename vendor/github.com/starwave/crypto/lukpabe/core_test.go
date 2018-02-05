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

func genFromMasterHelper(t *testing.T, params *Params, masterkey *MasterKey, tree AccessNode) *PrivateKey {
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

func attributeFromMasterHelper(t *testing.T, attrs AttributeSet, tree AccessNode, fail bool) *PrivateKey {
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

	// Rerandomize the key, and see if it still works
	Rerandomize(rand.Reader, params, key)
	decryptAndCheckHelper(t, key, ciphertext, message, fail)

	return key
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

func TestAppendLeaf(t *testing.T) {
	attrs := AttributeSet{big.NewInt(11), big.NewInt(13), big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{
			&AccessGate{
				Thresh: 1,
				Inputs: []AccessNode{
					&AccessLeaf{Attr: big.NewInt(11)},
					&AccessLeaf{Attr: big.NewInt(13)},
				},
			},
			&AccessLeaf{Attr: big.NewInt(15)},
		},
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

	decryptAndCheckHelper(t, key, ciphertext, message, false)

	AppendChildren(params, key, tree, &AccessLeaf{Attr: big.NewInt(17)}, &AccessLeaf{Attr: big.NewInt(19)})
	Rerandomize(rand.Reader, params, key)
	decryptAndCheckHelper(t, key, ciphertext, message, true)

	attrs = append(attrs, big.NewInt(17))
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, true)

	attrs = append(attrs, big.NewInt(19))
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, false)

	Rerandomize(rand.Reader, params, key)
	decryptAndCheckHelper(t, key, ciphertext, message, false)

	/* Check that the OR gate still works */

	attrs[0] = big.NewInt(10)
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, false)

	attrs[1] = big.NewInt(10)
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, true)
}

func TestAppendSubtree(t *testing.T) {
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

	decryptAndCheckHelper(t, key, ciphertext, message, false)

	subtree := &AccessGate{
		Thresh: 1,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(17)}, &AccessLeaf{Attr: big.NewInt(19)}},
	}
	AppendChildren(params, key, tree, subtree)
	Rerandomize(rand.Reader, params, key)
	decryptAndCheckHelper(t, key, ciphertext, message, true)

	attrs = append(attrs, big.NewInt(17))
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, false)
	Rerandomize(rand.Reader, params, key)
	decryptAndCheckHelper(t, key, ciphertext, message, false)

	attrs[2] = big.NewInt(19)
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, false)

	attrs[2] = big.NewInt(21)
	ciphertext = encryptHelper(t, params, attrs, message)
	decryptAndCheckHelper(t, key, ciphertext, message, true)
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

func KeyGenBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}

		leaves := make([]AccessNode, numAttributes)
		for i := 0; i != numAttributes; i++ {
			attr, err := rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
			leaves[i] = &AccessLeaf{Attr: attr}
		}

		tree := &AccessGate{
			Thresh: numAttributes,
			Inputs: leaves,
		}

		b.StartTimer()
		_, err = KeyGen(rand.Reader, params, master, tree)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyGen_5(b *testing.B) {
	KeyGenBenchmarkHelper(b, 5)
}

func BenchmarkKeyGen_10(b *testing.B) {
	KeyGenBenchmarkHelper(b, 10)
}

func BenchmarkKeyGen_15(b *testing.B) {
	KeyGenBenchmarkHelper(b, 15)
}

func BenchmarkKeyGen_20(b *testing.B) {
	KeyGenBenchmarkHelper(b, 20)
}

func QualifyKeyStartBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}

		leaves := make([]AccessNode, numAttributes)
		for i := 0; i != numAttributes; i++ {
			attr, err := rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
			leaves[i] = &AccessLeaf{Attr: attr}
		}

		tree := &AccessGate{
			Thresh: numAttributes - 1,
			Inputs: leaves[:numAttributes-1],
		}

		key, err := KeyGen(rand.Reader, params, master, tree)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		AppendChildren(params, key, tree, leaves[numAttributes-1])
		Rerandomize(rand.Reader, params, key)
		b.StopTimer()
	}
}

func BenchmarkQualifyKeyStart_5(b *testing.B) {
	QualifyKeyStartBenchmarkHelper(b, 5)
}

func BenchmarkQualifyKeyStart_10(b *testing.B) {
	QualifyKeyStartBenchmarkHelper(b, 10)
}

func BenchmarkQualifyKeyStart_15(b *testing.B) {
	QualifyKeyStartBenchmarkHelper(b, 15)
}

func BenchmarkQualifyKeyStart_20(b *testing.B) {
	QualifyKeyStartBenchmarkHelper(b, 20)
}

func QualifyKeyEndBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}

		leaves := make([]AccessNode, numAttributes)
		for i := 0; i != numAttributes; i++ {
			attr, err := rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
			leaves[i] = &AccessLeaf{Attr: attr}
		}

		tree := &AccessGate{
			Thresh: 1,
			Inputs: leaves[:1],
		}

		key, err := KeyGen(rand.Reader, params, master, tree)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		AppendChildren(params, key, tree, leaves[1:]...)
		Rerandomize(rand.Reader, params, key)
		b.StopTimer()
	}
}

func BenchmarkQualifyKeyEnd_5(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 5)
}

func BenchmarkQualifyKeyEnd_10(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 10)
}

func BenchmarkQualifyKeyEnd_15(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 15)
}

func BenchmarkQualifyKeyEnd_20(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 20)
}
