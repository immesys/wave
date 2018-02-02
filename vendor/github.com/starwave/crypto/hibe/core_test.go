package hibe

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

var LINEAR_HIERARCHY = []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
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

func TestTopLevel(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:1], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate key for the top level
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
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

func TestSecondLevelFromMaster(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:2], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from master key
	secondlevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:2])
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 8 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestSecondLevelFromParent(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:2], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := KeyGenFromParent(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 8 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := Setup(rand.Reader, 10)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, _, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_, err = Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkEncryptLarge(b *testing.B) {
	var err error
	b.StopTimer()

	// Generate a large ID
	idLength := 20
	id := make([]*big.Int, idLength)
	for j := 0; j != idLength; j++ {
		id[j], err = rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}
	}

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
		b.StartTimer()
		_, err = Encrypt(rand.Reader, params, id, message)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkKeyGenFromMaster(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		_, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkKeyGenFromParent(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		b.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := KeyGenFromParent(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		_, err := KeyGenFromParent(rand.Reader, params, secondlevelkey, LINEAR_HIERARCHY)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkDecryptWithKeyGeneratedFromMaster(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	// Generate secret key
	thirdlevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		decrypted := Decrypt(thirdlevelkey, ciphertext)
		b.StopTimer()
		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecryptWithKeyGeneratedFromParent(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		b.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := KeyGenFromParent(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		b.Fatal(err)
	}

	// Generate third level key from second level key
	thirdlevelkey, err := KeyGenFromParent(rand.Reader, params, secondlevelkey, LINEAR_HIERARCHY)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		decrypted := Decrypt(thirdlevelkey, ciphertext)
		b.StopTimer()
		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}
