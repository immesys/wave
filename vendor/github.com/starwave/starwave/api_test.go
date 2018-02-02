package starwave

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func randomMessageHelper(t *testing.T) []byte {
	message := make([]byte, 1027)
	_, err := rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func createEntityHelper(t *testing.T, nickname string) (*EntityDescriptor, *EntitySecret) {
	entity, secret, err := CreateEntity(rand.Reader, nickname)
	if err != nil {
		t.Fatal(err)
	}
	return entity, secret
}

func TestSimpleMessage(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, perm)
	if err != nil {
		t.Fatal(err)
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestExplicitHybrid(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, perm)
	if err != nil {
		t.Fatal(err)
	}

	symm := make([]byte, 32)
	esymm, err := GenerateEncryptedSymmetricKey(rand.Reader, hierarchy, perm, symm)
	if err != nil {
		t.Fatal(err)
	}

	dsymm := make([]byte, 32)
	retval := DecryptSymmetricKey(esymm, key, dsymm)
	if !bytes.Equal(dsymm, retval) {
		t.Fatal("DecryptSymmetricKey does not return buffer correctly")
	}
	if !bytes.Equal(symm, dsymm) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestGeneralRead(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermissionFromPath([]string{"a", "b", "c"}, []uint16{2017, 12, 6, 27, 1, 4})
	if err != nil {
		t.Fatal(err)
	}

	prefixperm, err := ParsePermissionFromPath([]string{"a", "b", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, prefixperm)
	if err != nil {
		t.Fatal(err)
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestBroadeningDelegation(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	prefix1perm, err := ParsePermissionFromPath([]string{"a", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	prefix2perm, err := ParsePermissionFromPath([]string{"a", "b", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermissionFromPath([]string{"a", "b", "c"}, []uint16{2017, 12, 6, 27, 1, 4})
	if err != nil {
		t.Fatal(err)
	}

	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	d1, err := DelegateBroadeningWithKey(rand.Reader, master, intermediate1, perm)
	if err != nil {
		t.Fatal(err)
	}

	d2, err := DelegateBroadening(rand.Reader, hierarchy, i1secret, intermediate2, prefix2perm)
	if err != nil {
		t.Fatal(err)
	}

	d3, err := DelegateBroadening(rand.Reader, hierarchy, i2secret, reader, prefix1perm)
	if err != nil {
		t.Fatal(err)
	}

	key := ResolveChain(d1, []*BroadeningDelegation{d2, d3}, rsecret)
	if key == nil {
		t.Fatal("Could not resolve chain of delegations")
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func getTimesHelper(t *testing.T) (time.Time, time.Time, time.Time, time.Time) {
	start, err := time.Parse(time.RFC822Z, "01 Jan 15 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	end1, err := time.Parse(time.RFC822Z, "06 Mar 18 06:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	end2, err := time.Parse(time.RFC822Z, "01 Apr 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	end3, err := time.Parse(time.RFC822Z, "04 Apr 19 02:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	return start, end1, end2, end3
}

func TestDelegationBundleBroadening(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	start, end1, end2, end3 := getTimesHelper(t)

	_, asecret := createEntityHelper(t, "Authority")
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{master}, intermediate1, "a/b/c/d/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, []*DecryptionKey{}, intermediate2, "a/b/c/*", start, end2)
	if err != nil {
		t.Fatal(err)
	}

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, []*DecryptionKey{}, reader, "a/b/c/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key == nil {
		t.Fatal("Could not derive key from chain")
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestDelegationBundleNotAChain(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	start, end1, end2, end3 := getTimesHelper(t)

	_, asecret := createEntityHelper(t, "Authority")
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{master}, intermediate1, "a/b/c/d/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, []*DecryptionKey{}, intermediate2, "a/b/c/d/f", start, end2)
	if err != nil {
		t.Fatal(err)
	}

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, []*DecryptionKey{}, reader, "a/b/c/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key != nil {
		t.Fatal("Derived key from bogus chain")
	}
}

func TestDelegationBundleNoKey(t *testing.T) {
	hierarchy, _, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	start, end1, end2, end3 := getTimesHelper(t)

	_, asecret := createEntityHelper(t, "Authority")
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{}, intermediate1, "a/b/c/d/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, []*DecryptionKey{}, intermediate2, "a/b/c/*", start, end2)
	if err != nil {
		t.Fatal(err)
	}

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, []*DecryptionKey{}, reader, "a/b/c/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key != nil {
		t.Fatal("Derived key from bogus chain")
	}
}

func TestDelegationBundleNotBroadening(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	start, end1, end2, end3 := getTimesHelper(t)

	_, asecret := createEntityHelper(t, "Authority")
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{master}, intermediate1, "a/b/c/d/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, []*DecryptionKey{}, intermediate2, "a/b/*", start, end2)
	if err != nil {
		t.Fatal(err)
	}

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, []*DecryptionKey{}, reader, "a/b/c/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key != nil {
		t.Fatal("Derived key from bogus chain")
	}
}

func TestDelegationBundleWithTransferredKeys(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	start, end1, end2, end3 := getTimesHelper(t)

	_, asecret := createEntityHelper(t, "Authority")
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	reader, rsecret := createEntityHelper(t, "Reader")

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{master}, intermediate1, "a/b/c/d/*", start, end2)
	if err != nil {
		t.Fatal(err)
	}

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, ExtractKeys(db1, i1secret), intermediate2, "a/b/c/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, ExtractKeys(db2, i2secret), reader, "a/b/c/d/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key == nil {
		t.Fatal("Could not derive key from chain")
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}
