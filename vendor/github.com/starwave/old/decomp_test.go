package core

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/hibe"
)

func TestCiphertextDecomposition(t *testing.T) {
	// Set up parameters
	params, masterKey, err := hibe.Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	params.Precache()

	// Set up URI
	uriPath, err := ParseURI("p/q/r/u")
	if err != nil {
		t.Fatal(err)
	}

	// Set up time
	date, err := time.Parse(time.RFC822Z, "09 Oct 17 21:00 -0700")
	if err != nil {
		t.Fatal(err)
	}
	timePath, err := ParseTime(date)
	if err != nil {
		t.Fatal(err)
	}

	pt, gt := cryptutils.GenerateKey(make([]byte, 16))

	ciphertext := EncryptDecomposed(gt, params, uriPath, timePath)

	id1 := make(ID, 0, 8)
	id1 = append(id1, uriPath...)
	id1 = append(id1, timePath...)

	sk1, err := hibe.KeyGenFromMaster(rand.Reader, params, masterKey, id1.HashToZp())
	if err != nil {
		t.Fatal(err)
	}

	gt1 := DecryptDecomposed(ciphertext, id1, sk1)
	pt1 := cryptutils.GTToSecretKey(gt1, make([]byte, 16))

	if !bytes.Equal(pt, pt1) {
		t.Fatalf("Original and decrypted plaintexts differ")
	}
}
