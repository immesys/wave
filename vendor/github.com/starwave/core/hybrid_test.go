package core

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

func oaqueHelper(t *testing.T) (*oaque.Params, *oaque.PreparedAttributeList, *oaque.PrivateKey) {
	params, master, err := oaque.Setup(rand.Reader, 20)
	if err != nil {
		t.Fatal(err)
	}

	attrs := make(oaque.AttributeList)
	attrs[2] = big.NewInt(6)

	precomputed := oaque.PrepareAttributeSet(params, attrs)
	key, err := oaque.KeyGen(nil, params, master, attrs)
	if err != nil {
		t.Fatal(err)
	}

	return params, precomputed, key
}

func TestHybridSymmetricKey(t *testing.T) {
	params, precomputed, key := oaqueHelper(t)

	var symm1 = make([]byte, 32)
	ciphertext, err := GenerateEncryptedSymmetricKey(rand.Reader, params, precomputed, symm1)
	if err != nil {
		t.Fatal(err)
	}

	var symm2 = make([]byte, 32)
	DecryptSymmetricKey(key, ciphertext, symm2)

	if !bytes.Equal(symm1, symm2) {
		t.Fatal("Generated and decrypted symmetric keys differ")
	}
}

func TestHybridEncryption(t *testing.T) {
	message := make([]byte, 1024)
	_, err := rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	params, precomputed, key := oaqueHelper(t)

	ekey, emsg, err := HybridEncrypt(rand.Reader, params, precomputed, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, success := HybridDecrypt(ekey, emsg, key)
	if !success {
		t.Fatal("Hybrid decryption failed")
	}

	if !bytes.Equal(message, decrypted) {
		t.Fatal("Hybrid decryption gave the wrong result")
	}

	bigidx, err := rand.Int(rand.Reader, big.NewInt(int64(len(emsg))))
	if err != nil {
		t.Fatal(err)
	}
	idx := bigidx.Uint64()
	emsg[idx] = ^emsg[idx]
	_, success = HybridDecrypt(ekey, emsg, key)
	if success {
		t.Fatal("Decryption succeeded after tampering with ciphertext")
	}
}
