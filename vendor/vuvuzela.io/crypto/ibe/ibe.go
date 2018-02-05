// Copyright 2016 The Alpenhorn Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ibe implements Identity-Based Encryption (IBE).
//
// This package implements Hybrid-IBE from
// "Identity Based Encryption Without Redundancy"
// http://cseweb.ucsd.edu/~mihir/cse208-06/libert-quisquater-ibe-acns-05.pdf.
// This schemes transforms the BF-IBE scheme (BasicIndent) into an
// IND-ID-CCA2 secure scheme.
package ibe // import "vuvuzela.io/crypto/ibe"

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"

	"vuvuzela.io/crypto/bn256"
)

const sizeOfG1 = 64
const Overhead = sizeOfG1 + secretbox.Overhead

type MasterPublicKey struct {
	g1 *bn256.G1
}

type MasterPrivateKey struct {
	s *big.Int
}

type IdentityPrivateKey struct {
	d *bn256.G2
	q *bn256.G2
}

func (priv *MasterPrivateKey) MarshalBinary() ([]byte, error) {
	return priv.s.Bytes(), nil
}
func (priv *MasterPrivateKey) UnmarshalBinary(data []byte) error {
	priv.s = new(big.Int)
	priv.s.SetBytes(data)
	return nil
}
func Setup(random io.Reader) (*MasterPublicKey, *MasterPrivateKey) {
	secret, err := rand.Int(random, bn256.Order)
	if err != nil {
		panic(err)
	}
	public := new(bn256.G1).ScalarBaseMult(secret)
	return &MasterPublicKey{public}, &MasterPrivateKey{secret}
}

func Extract(priv *MasterPrivateKey, id []byte) *IdentityPrivateKey {
	q := new(bn256.G2).HashToPoint(id)
	d := new(bn256.G2).ScalarMult(q, priv.s)
	return &IdentityPrivateKey{d: d, q: q}
}

type Ciphertext struct {
	U *bn256.G1
	V []byte
}

func (c Ciphertext) String() string {
	return fmt.Sprintf("ibe.Ciphertext(%s, %x)", c.U, c.V)
}

func (c Ciphertext) MarshalBinary() ([]byte, error) {
	return append(c.U.Marshal(), c.V...), nil
}

func (c *Ciphertext) UnmarshalBinary(data []byte) error {
	var ok bool
	c.U, ok = new(bn256.G1).Unmarshal(data[0:64])
	if !ok {
		return fmt.Errorf("failed to unmarshal ciphertext")
	}
	c.V = data[64:]
	return nil
}

func Encrypt(random io.Reader, pub *MasterPublicKey, id []byte, msg []byte) Ciphertext {
	q := new(bn256.G2).HashToPoint(id)
	g := bn256.Pair(pub.g1, q)

	r, err := rand.Int(random, bn256.Order)
	if err != nil {
		panic(err)
	}

	rp := new(bn256.G1).ScalarBaseMult(r)
	er := new(bn256.GT).ScalarMult(g, r)

	shake := sha3.NewShake256()
	shake.Write(q.Marshal())
	shake.Write(rp.Marshal())
	shake.Write(er.Marshal())

	var sk [32]byte
	shake.Read(sk[:])

	box := secretbox.Seal(nil, msg, new([24]byte), &sk)

	return Ciphertext{
		U: rp,
		V: box,
	}
}

func Decrypt(priv *IdentityPrivateKey, c Ciphertext) ([]byte, bool) {
	e := bn256.Pair(c.U, priv.d)

	shake := sha3.NewShake256()
	shake.Write(priv.q.Marshal())
	shake.Write(c.U.Marshal())
	shake.Write(e.Marshal())

	var sk [32]byte
	shake.Read(sk[:])

	return secretbox.Open(nil, c.V, new([24]byte), &sk)
}

func (pk *MasterPublicKey) Aggregate(keys ...*MasterPublicKey) *MasterPublicKey {
	pk.g1 = new(bn256.G1)
	for _, key := range keys {
		pk.g1.Add(pk.g1, key.g1)
	}
	return pk
}

func (sk *IdentityPrivateKey) Aggregate(keys ...*IdentityPrivateKey) *IdentityPrivateKey {
	sk.d = new(bn256.G2)
	for _, key := range keys {
		sk.d.Add(sk.d, key.d)
	}
	sk.q = new(bn256.G2).Set(keys[0].q) // TODO check all the same
	return sk
}

func (pk *MasterPublicKey) MarshalBinary() ([]byte, error) {
	return pk.g1.Marshal(), nil
}

func (pk *MasterPublicKey) UnmarshalBinary(data []byte) error {
	pk.g1 = new(bn256.G1)
	_, ok := pk.g1.Unmarshal(data)
	if !ok {
		return fmt.Errorf("failed to decode ibe.MasterPublicKey")
	}
	return nil
}

func (pk *MasterPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.g1.Marshal())
}

func (pk *MasterPublicKey) UnmarshalJSON(data []byte) error {
	var b []byte
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	pk.g1 = new(bn256.G1)
	_, ok := pk.g1.Unmarshal(b)
	if !ok {
		return fmt.Errorf("failed to decode ibe.MasterPublicKey")
	}
	return nil
}

func (sk *IdentityPrivateKey) MarshalBinary() ([]byte, error) {
	d := sk.d.Marshal()
	q := sk.q.Marshal()
	return append(d, q...), nil
}

func (sk *IdentityPrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != 256 {
		return fmt.Errorf("short data: %d", len(data))
	}
	sk.d = new(bn256.G2)
	_, ok := sk.d.Unmarshal(data[:128])
	if !ok {
		return fmt.Errorf("failed to decode ibe.IdentityPrivateKey")
	}
	sk.q = new(bn256.G2)
	_, ok = sk.q.Unmarshal(data[128:])
	if !ok {
		return fmt.Errorf("failed to decode ibe.IdentityPrivateKey")
	}
	return nil
}
