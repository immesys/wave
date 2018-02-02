package starwave

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func remarshalHelper(m Marshallable) {
	b := m.Marshal()
	success := m.Unmarshal(b)
	if !success {
		panic("Remarshalling failed")
	}
}

func TestBroadeningDelegationWithMarshalling(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	remarshalHelper(hierarchy)
	remarshalHelper(master)

	prefix1perm, err := ParsePermissionFromPath([]string{"a", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	remarshalHelper(prefix1perm)

	prefix2perm, err := ParsePermissionFromPath([]string{"a", "b", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	remarshalHelper(prefix2perm)

	perm, err := ParsePermissionFromPath([]string{"a", "b", "c"}, []uint16{2017, 12, 6, 27, 1, 4})
	if err != nil {
		t.Fatal(err)
	}

	remarshalHelper(perm)

	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	remarshalHelper(intermediate1)
	remarshalHelper(i1secret)
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	remarshalHelper(intermediate2)
	remarshalHelper(i2secret)
	reader, rsecret := createEntityHelper(t, "Reader")
	remarshalHelper(reader)
	remarshalHelper(rsecret)

	d1, err := DelegateBroadeningWithKey(rand.Reader, master, intermediate1, perm)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(d1)

	d2, err := DelegateBroadening(rand.Reader, hierarchy, i1secret, intermediate2, prefix2perm)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(d2)

	d3, err := DelegateBroadening(rand.Reader, hierarchy, i2secret, reader, prefix1perm)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(d3)

	/*
	 * This isn't how FullDelegation is supposed to be used, but it is good
	 * enough for testing marshalling.
	 */
	/*fd := &FullDelegation{
		Permissions: d2.Delegation.Key.Permissions,
		Broad:       d2,
		Narrow:      []*BroadeningDelegationWithKey{d1, d1},
	}
	remarshalHelper(fd)
	d1 = fd.Narrow[1]
	d2 = fd.Broad*/

	key := ResolveChain(d1, []*BroadeningDelegation{d2, d3}, rsecret)
	if key == nil {
		t.Fatal("Could not resolve chain of delegations")
	}
	remarshalHelper(key)

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(emsg)

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestPanicOnUnexpectedMessage(t *testing.T) {
	defer func() {
		recover()
	}()

	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	marshalled := hierarchy.Marshal()
	master.Unmarshal(marshalled)

	t.Fatal("Did not panic when unmarshalling unexpected message")
}

func TestDelegationBundleWithMarshalling(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	remarshalHelper(hierarchy)
	remarshalHelper(master)

	start, end1, end2, end3 := getTimesHelper(t)

	authority, asecret := createEntityHelper(t, "Authority")
	remarshalHelper(authority)
	remarshalHelper(asecret)
	intermediate1, i1secret := createEntityHelper(t, "Intermediate 1")
	remarshalHelper(intermediate1)
	remarshalHelper(i1secret)
	intermediate2, i2secret := createEntityHelper(t, "Intermediate 2")
	remarshalHelper(intermediate2)
	remarshalHelper(i2secret)
	reader, rsecret := createEntityHelper(t, "Reader")
	remarshalHelper(reader)
	remarshalHelper(rsecret)

	db1, err := DelegateBundle(rand.Reader, hierarchy, asecret, []*DecryptionKey{master}, intermediate1, "a/b/c/d/*", start, end2)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(db1)

	db2, err := DelegateBundle(rand.Reader, hierarchy, i1secret, ExtractKeys(db1, i1secret), intermediate2, "a/b/c/*", start, end1)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(db2)

	db3, err := DelegateBundle(rand.Reader, hierarchy, i2secret, ExtractKeys(db2, i2secret), reader, "a/b/c/d/*", start, end3)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(db3)

	targettime, err := time.Parse(time.RFC822Z, "01 Mar 18 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/d/e", targettime)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(perm)

	key := DeriveKey([]*DelegationBundle{db1, db2, db3}, perm, rsecret)
	if key == nil {
		t.Fatal("Could not derive key from chain")
	}
	remarshalHelper(key)

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}
	remarshalHelper(emsg)

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}
