package oaque

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

func NewSignatureMessage(t *testing.T) *big.Int {
	num, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return num
}

func encryptHelper(t *testing.T, params *Params, attrs AttributeList, message *bn256.GT) *Ciphertext {
	ciphertext, err := Encrypt(nil, params, attrs, message)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func verifyHelper(t *testing.T, params *Params, sigparams *SignatureParams, attrs AttributeList, signature *Signature, message *big.Int) {
	correct := Verify(params, sigparams, attrs, signature, message)
	if !correct {
		t.Fatal("Signature is invalid")
	}
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey *MasterKey, attrs AttributeList) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGen(nil, params, masterkey, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func qualifyHelper(t *testing.T, params *Params, key *PrivateKey, attrs AttributeList) *PrivateKey {
	key, err := QualifyKey(nil, params, key, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, key *PrivateKey, ciphertext *Ciphertext, message *bn256.GT) {
	decrypted := Decrypt(key, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func signHelper(t *testing.T, params *Params, sigparams *SignatureParams, key *PrivateKey, message *big.Int) *Signature {
	signature, err := Sign(nil, params, sigparams, key, message)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func attributeFromMasterHelper(t *testing.T, attrs AttributeList) {
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
	key := genFromMasterHelper(t, params, masterkey, attrs)

	decryptAndCheckHelper(t, key, ciphertext, message)
}

func attributeFromMasterSignatureHelper(t *testing.T, attrs AttributeList) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}
	sigparams, err := SignatureSetup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to sign
	message := NewSignatureMessage(t)

	// Generate key for the attributes
	key := genFromMasterHelper(t, params, masterkey, attrs)

	// Sign the message
	signature := signHelper(t, params, sigparams, key, message)

	// Verify the signature
	verifyHelper(t, params, sigparams, attrs, signature, message)
}

func TestSingleAttributeEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{0: big.NewInt(0)})
}

func TestSingleSparseAttributeEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(0)})
}

func TestMultipleSparseAttributesEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(0), 8: big.NewInt(123)})
}

func TestSingleAttributeSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{0: big.NewInt(0)})
}

func TestSingleSparseAttributeSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{1: big.NewInt(0)})
}

func TestMultipleSparseAttributesSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{1: big.NewInt(0), 8: big.NewInt(123)})
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := qualifyHelper(t, params, key1, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestNonDelegableKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := NonDelegableKey(params, key1, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestDecryptWithMaster(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	decrypted := DecryptWithMaster(masterkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestNonDelegableKeyFromMaster(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in one step
	key2 := NonDelegableKeyFromMaster(params, masterkey, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestPartialDelegation(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4), 6: nil}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}
	attrs3 := AttributeList{2: big.NewInt(4), 6: big.NewInt(124)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)

	// This should work fine
	ciphertext := encryptHelper(t, params, attrs2, message)
	key2 := qualifyHelper(t, params, key1, attrs2)
	decryptAndCheckHelper(t, key2, ciphertext, message)

	// This should not work, because slot 6 is hidden
	ciphertext = encryptHelper(t, params, attrs3, message)
	key3 := qualifyHelper(t, params, key1, attrs3)
	decrypted := Decrypt(key3, ciphertext)
	if bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Managed to fill hidden slot")
	}
}

func TestResampleKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2, err := ResampleKey(nil, params, PrepareAttributeSet(params, attrs1), key1, true)
	if err != nil {
		t.Fatal(err)
	}
	key3 := NonDelegableKey(params, key2, attrs2)

	decryptAndCheckHelper(t, key3, ciphertext, message)
}

func TestAdditiveRandomness(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	r, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{7: big.NewInt(123)}
	attrs3 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs3, message)

	// Generate key in two steps, in two different ways
	key1a, err := KeyGen(r, params, masterkey, attrs1)
	if err != nil {
		t.Fatal(err)
	}
	key1b, err := QualifyKey(s, params, key1a, attrs3)
	if err != nil {
		t.Fatal(err)
	}

	key2a, err := KeyGen(s, params, masterkey, attrs2)
	if err != nil {
		t.Fatal(err)
	}
	key2b, err := QualifyKey(r, params, key2a, attrs3)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure both keys work...
	decryptAndCheckHelper(t, key1b, ciphertext, message)
	decryptAndCheckHelper(t, key2b, ciphertext, message)

	// Both keys should be equal to a key generated with randomness r + s
	rpluss := new(big.Int).Add(r, s)
	key3, err := KeyGen(rpluss, params, masterkey, attrs3)
	if err != nil {
		t.Fatal(err)
	}
	decryptAndCheckHelper(t, key3, ciphertext, message)

	if !bytes.Equal(key1b.Marshal(), key3.Marshal()) {
		t.Fatal("key1b and key3 differ")
	}

	if !bytes.Equal(key2b.Marshal(), key3.Marshal()) {
		t.Fatal("key2b and key3 differ")
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
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

func EncryptCachedBenchmarkHelper(b *testing.B, numAttributes int) {
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		precomputed := PrepareAttributeSet(params, attrs)

		b.StartTimer()
		_, err = EncryptPrecomputed(nil, params, precomputed, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptCached_5(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 5)
}

func BenchmarkEncryptCached_10(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 10)
}

func BenchmarkEncryptCached_15(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 15)
}

func BenchmarkEncryptCached_20(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 20)
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(nil, params, attrs, message)
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

func DecryptWithMasterBenchmarkHelper(b *testing.B, numAttributes int) {
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		ciphertext, err := Encrypt(nil, params, attrs, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		decrypted := DecryptWithMaster(master, ciphertext)
		b.StopTimer()

		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecryptWithMaster_5(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 5)
}

func BenchmarkDecryptWithMaster_10(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 10)
}

func BenchmarkDecryptWithMaster_15(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 15)
}

func BenchmarkDecryptWithMaster_20(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 20)
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		pseudomaster, err := KeyGen(nil, params, master, AttributeList{})
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(nil, params, attrs, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		key := NonDelegableKey(params, pseudomaster, attrs)
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

func SignBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}
	sigparams, err := SignatureSetup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := RandomInZp(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_, err = Sign(nil, params, sigparams, key, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_5(b *testing.B) {
	SignBenchmarkHelper(b, 5)
}

func BenchmarkSign_10(b *testing.B) {
	SignBenchmarkHelper(b, 10)
}

func BenchmarkSign_15(b *testing.B) {
	SignBenchmarkHelper(b, 15)
}

func BenchmarkSign_20(b *testing.B) {
	SignBenchmarkHelper(b, 20)
}

func VerifyBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}
	sigparams, err := SignatureSetup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := RandomInZp(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		signature, err := Sign(nil, params, sigparams, key, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		correct := Verify(params, sigparams, attrs, signature, message)
		b.StopTimer()

		if !correct {
			b.Fatal("Signature is not valid")
		}
	}
}

func BenchmarkVerify_5(b *testing.B) {
	VerifyBenchmarkHelper(b, 5)
}

func BenchmarkVerify_10(b *testing.B) {
	VerifyBenchmarkHelper(b, 10)
}

func BenchmarkVerify_15(b *testing.B) {
	VerifyBenchmarkHelper(b, 15)
}

func BenchmarkVerify_20(b *testing.B) {
	VerifyBenchmarkHelper(b, 20)
}

func VerifyCachedBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}
	sigparams, err := SignatureSetup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := RandomInZp(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		signature, err := Sign(nil, params, sigparams, key, message)
		if err != nil {
			b.Fatal(err)
		}

		precomputed := PrepareAttributeSet(params, attrs)

		b.StartTimer()
		correct := VerifyPrecomputed(params, sigparams, precomputed, signature, message)
		b.StopTimer()

		if !correct {
			b.Fatal("Signature is not valid")
		}
	}
}

func BenchmarkVerifyCached_5(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 5)
}

func BenchmarkVerifyCached_10(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 10)
}

func BenchmarkVerifyCached_15(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 15)
}

func BenchmarkVerifyCached_20(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 20)
}

func ResampleKeyBenchmarkHelper(b *testing.B, numAttributes int, delegable bool) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		precomputed := PrepareAttributeSet(params, attrs)

		b.StartTimer()
		_, err = ResampleKey(nil, params, precomputed, key, delegable)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResampleKey_5(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 5, false)
}

func BenchmarkResampleKey_10(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 10, false)
}

func BenchmarkResampleKey_15(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 15, false)
}

func BenchmarkResampleKey_20(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 20, false)
}

func QualifyKeyStartBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		attrs[AttributeIndex(numAttributes-1)], err = rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_, err = QualifyKey(nil, params, key, attrs)
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

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, AttributeList{0: attrs[0]})
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_, err = QualifyKey(nil, params, key, attrs)
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
