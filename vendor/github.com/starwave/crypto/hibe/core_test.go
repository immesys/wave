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
	toplevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
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

func TestKeyGen(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the ID
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate key from master key
	secondlevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY)
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 7 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := QualifyKey(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY)
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 7 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestNonDelegableKeyFromMaster(t *testing.T) {
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
	toplevelkey := NonDelegableKeyFromMaster(params, key, LINEAR_HIERARCHY[:1])

	// Generate second level key from top level key
	secondlevelkey, err := QualifyKey(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
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

func TestNonDelegableKey(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY, message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := NonDelegableKey(params, toplevelkey, LINEAR_HIERARCHY)
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 7 {
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

func BenchmarkKeyGen(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		_, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkQualifyKey(b *testing.B) {
	b.StopTimer()

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		b.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		b.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := QualifyKey(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		_, err := QualifyKey(rand.Reader, params, secondlevelkey, LINEAR_HIERARCHY)
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
	thirdlevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY)
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
	toplevelkey, err := KeyGen(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		b.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := QualifyKey(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		b.Fatal(err)
	}

	// Generate third level key from second level key
	thirdlevelkey, err := QualifyKey(rand.Reader, params, secondlevelkey, LINEAR_HIERARCHY)
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

		id := make([]*big.Int, numAttributes)
		for i := range id {
			id[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StartTimer()
		_, err = Encrypt(rand.Reader, params, id, message)
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

func DecryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		id := make([]*big.Int, numAttributes)
		for i := range id {
			id[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(rand.Reader, params, master, id)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(rand.Reader, params, id, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		decrypted := Decrypt(key, ciphertext)
		b.StopTimer()

		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecrypt_5(b *testing.B) {
	DecryptBenchmarkHelper(b, 5)
}

func BenchmarkDecrypt_10(b *testing.B) {
	DecryptBenchmarkHelper(b, 10)
}

func BenchmarkDecrypt_15(b *testing.B) {
	DecryptBenchmarkHelper(b, 15)
}

func BenchmarkDecrypt_20(b *testing.B) {
	DecryptBenchmarkHelper(b, 20)
}

func NonDelegableKeyBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		id := make([]*big.Int, numAttributes)
		for i := range id {
			id[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		pseudomaster, err := KeyGen(rand.Reader, params, master, []*big.Int{})
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(rand.Reader, params, id, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		key, _ := NonDelegableKey(params, pseudomaster, id)
		b.StopTimer()

		decrypted := Decrypt(key, ciphertext)
		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkNonDelegableKey_5(b *testing.B) {
	NonDelegableKeyBenchmarkHelper(b, 5)
}

func BenchmarkNonDelegableKey_10(b *testing.B) {
	NonDelegableKeyBenchmarkHelper(b, 10)
}

func BenchmarkNonDelegableKey_15(b *testing.B) {
	NonDelegableKeyBenchmarkHelper(b, 15)
}

func BenchmarkNonDelegableKey_20(b *testing.B) {
	NonDelegableKeyBenchmarkHelper(b, 20)
}

func QualifyKeyStartBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}

		id := make([]*big.Int, numAttributes)
		for i := range id {
			id[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(rand.Reader, params, master, id[:len(id)-1])
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_, err = QualifyKey(rand.Reader, params, key, id)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
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

		id := make([]*big.Int, numAttributes)
		for i := range id {
			id[i], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(rand.Reader, params, master, id[:1])
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_, err = QualifyKey(rand.Reader, params, key, id)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
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
