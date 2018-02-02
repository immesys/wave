package core

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/hibe"
)

func generateTopLevel() (*hibe.Params, *hibe.PrivateKey) {
	params, masterKey, err := hibe.Setup(rand.Reader, 20)
	if err != nil {
		panic(err)
	}
	topKey := CreateTopLevel(rand.Reader, params, masterKey)
	return params, topKey
}

func assertKeyIsForID(t *testing.T, params *hibe.Params, key *hibe.PrivateKey, id ID) {
	buffer := make([]byte, 16)
	_, err := rand.Read(buffer)
	if err != nil {
		panic(err)
	}

	gt := cryptutils.HashToGT(buffer)

	ciphertext, err := hibe.Encrypt(rand.Reader, params, id.HashToZp(), gt)
	if err != nil {
		panic(err)
	}

	gtDecrypted := hibe.Decrypt(key, ciphertext)

	if !bytes.Equal(gt.Marshal(), gtDecrypted.Marshal()) {
		t.Fatal("Generated key does not work for the expected ID")
	}
}

func assertIDsAreEqual(t *testing.T, id1 ID, id2 ID) {
	if len(id1) != len(id2) {
		t.Fatalf("%s and %s have different lengths", id1, id2)
	}

	for i, comp1 := range id1 {
		comp2 := id2[i]
		if !bytes.Equal(comp1.Representation(), comp2.Representation()) {
			t.Fatalf("%s and %s differ in component %d", id1, id2, i)
		}
	}
}

func TestCreateTopLevel(t *testing.T) {
	params, topKey := generateTopLevel()
	id, err := ParseURI("a/*")
	if err != nil {
		t.Fatal(err)
	}

	idKey := GenerateChild(params, topKey, id)
	assertKeyIsForID(t, params, idKey, id)
}

func TestCreateDescendant(t *testing.T) {
	params, topKey := generateTopLevel()
	uriPath, err := ParseURI("a/b/*")
	if err != nil {
		t.Fatal(err)
	}

	date, err := time.Parse(time.RFC822Z, "09 Oct 17 21:00 -0700")
	if err != nil {
		t.Fatal(err)
	}
	timePath, err := ParseTime(date)
	if err != nil {
		t.Fatal(err)
	}

	id, key, err := GenerateDescendant(params, topKey, ID{}, uriPath, timePath)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyIsForID(t, params, key, id)
	assertIDsAreEqual(t, id, JoinIDs(uriPath, timePath))

	qualifiedURIPath, err := ParseURI("a/b/c")
	if err != nil {
		t.Fatal(err)
	}

	subID, subKey, err := GenerateDescendant(params, key, id, qualifiedURIPath, timePath)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyIsForID(t, params, subKey, subID)
	assertIDsAreEqual(t, subID, JoinIDs(id, qualifiedURIPath[2:]))
}
