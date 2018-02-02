// Copyright 2016 The Alpenhorn Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ibe

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

func TestCorrectness(t *testing.T) {
	masterPub, masterPriv := Setup(rand.Reader)

	idAlice := Extract(masterPriv, []byte("alice@example.com"))
	idBob := Extract(masterPriv, []byte("bob@example.com"))

	msg := make([]byte, 64)
	rand.Read(msg)

	c := Encrypt(rand.Reader, masterPub, []byte("bob@example.com"), msg)

	msg2, ok := Decrypt(idBob, c)
	if !ok {
		t.Fatalf("authentication failed")
	}
	if bytes.Compare(msg, msg2) != 0 {
		t.Fatalf("messages differ: expected=%#v got=%#v", msg, msg2)
	}

	_, ok = Decrypt(idAlice, c)
	if ok {
		t.Fatalf("expected authentication to fail")
	}
}

func TestCiphertextSize(t *testing.T) {
	masterPub, _ := Setup(rand.Reader)

	msg := []byte("12345")
	c := Encrypt(rand.Reader, masterPub, []byte("bob@example.com"), msg)
	bs, _ := c.MarshalBinary()
	if len(bs) != len(msg)+Overhead {
		t.Fatalf("expecting ciphertext size %d but got %d bytes instead", len(msg)+Overhead, len(bs))
	}
}

func TestDistributivity(t *testing.T) {
	for i := 0; i < 1000; i++ {
		secret1, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			panic(err)
		}
		secret2, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			panic(err)
		}
		public1 := new(bn256.G1).ScalarBaseMult(secret1)
		public2 := new(bn256.G1).ScalarBaseMult(secret2)
		publicX := new(bn256.G1).Add(public1, public2)

		secret := new(big.Int).Add(secret1, secret2)
		publicY := new(bn256.G1).ScalarBaseMult(secret)

		if bytes.Compare(publicX.Marshal(), publicY.Marshal()) != 0 {
			t.Fatalf("does not distribute: secret1=%s  secret2=%s", secret1, secret2)
		}
	}
}

func TestOnion(t *testing.T) {
	for i := 0; i < 100; i++ {
		masterPub1, masterPriv1 := Setup(rand.Reader)
		masterPub2, masterPriv2 := Setup(rand.Reader)

		idAlice1 := Extract(masterPriv1, []byte("alice@example.com"))
		idAlice2 := Extract(masterPriv2, []byte("alice@example.com"))

		combinedMasterPublic := new(MasterPublicKey).Aggregate(masterPub1, masterPub2)
		combinedIDAlice := new(IdentityPrivateKey).Aggregate(idAlice1, idAlice2)

		msg := make([]byte, 32)
		rand.Read(msg)

		c := Encrypt(rand.Reader, combinedMasterPublic, []byte("alice@example.com"), msg)

		msg2, ok := Decrypt(combinedIDAlice, c)
		if !ok {
			t.Fatalf("decryption failed")
		}

		if bytes.Compare(msg, msg2) != 0 {
			t.Fatalf("expected the same message")
		}

		msgBad, _ := Decrypt(idAlice1, c)
		if bytes.Compare(msg, msgBad) == 0 {
			t.Fatalf("did not expect the same message")
		}
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	for i := 0; i < 1000; i++ {
		masterPub, masterPriv := Setup(rand.Reader)

		msg := make([]byte, 32)
		rand.Read(msg)
		ctxt := Encrypt(rand.Reader, masterPub, []byte("alice@example.com"), msg)

		idAlice := Extract(masterPriv, []byte("alice@example.com"))
		data, _ := idAlice.MarshalBinary()
		id := new(IdentityPrivateKey)
		id.UnmarshalBinary(data)

		_, ok := Decrypt(id, ctxt)
		if !ok {
			t.Fatalf("error decrypting")
		}
	}
}

func BenchmarkExtract(b *testing.B) {
	_, masterPriv := Setup(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(masterPriv, []byte("foo@bar.com"))
	}
}

func BenchmarkDecrypt(b *testing.B) {
	masterPub, masterPriv := Setup(rand.Reader)

	msg := make([]byte, 32)
	rand.Read(msg)

	ctxt := Encrypt(rand.Reader, masterPub, []byte("alice@example.com"), msg)
	idAlice := Extract(masterPriv, []byte("alice@example.com"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := Decrypt(idAlice, ctxt)
		if !ok {
			b.Fatalf("error decrypting")
		}
	}
}

// Confirm that decrypting random bytes take the same amount
// of time as decrypting a valid ciphertext.
func BenchmarkDecryptRandom(b *testing.B) {
	masterPub, masterPriv := Setup(rand.Reader)

	msg := make([]byte, 32)
	rand.Read(msg)

	idAlice := Extract(masterPriv, []byte("alice@example.com"))

	validCtxt := Encrypt(rand.Reader, masterPub, []byte("alice@example.com"), msg)
	validBytes, _ := validCtxt.MarshalBinary()

	invalidBytes := make([]byte, len(validBytes))
	rand.Read(invalidBytes)
	var invalidCtxt Ciphertext
	err := invalidCtxt.UnmarshalBinary(invalidBytes)
	if err != nil {
		b.Fatalf("failed to unmarshal ciphertext: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := Decrypt(idAlice, invalidCtxt)
		if ok {
			b.Fatalf("expected decryption to fail")
		}
	}
}

func TestMarshalJSON(t *testing.T) {
	masterPub, _ := Setup(rand.Reader)
	bs, err := json.Marshal(masterPub)
	if err != nil {
		t.Fatalf("json.Marshal: %s", err)
	}

	newMasterPub := new(MasterPublicKey)
	err = json.Unmarshal(bs, newMasterPub)
	if err != nil {
		t.Fatalf("json.Unmarshal: %s", err)
	}

	expected, _ := masterPub.MarshalBinary()
	actually, _ := newMasterPub.MarshalBinary()

	if !bytes.Equal(expected, actually) {
		t.Fatalf("want %x\ngot  %x", expected, actually)
	}
}
