package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/immesys/wave/storage/simplehttp"
	"golang.org/x/crypto/sha3"
)

func ParsePrivateKey(in []byte) (*ecdsa.PrivateKey, error) {
	der, trailing := pem.Decode(in)
	if len(trailing) != 0 {
		return nil, fmt.Errorf("key is invalid")
	}
	priv, err := x509.ParseECPrivateKey(der.Bytes)
	if err != nil {
		panic(err)
	}
	return priv, err
}
func MakeMergePromise(key []byte, valhash []byte, signingkey *ecdsa.PrivateKey) (*simplehttp.MergePromise, error) {
	if signingkey == nil {
		panic("no signing key!")
	}
	p := &simplehttp.MergePromiseTBS{
		Key:     key,
		ValHash: valhash,
		MergeBy: time.Now().Add(time.Hour).UnixNano() / 1e6,
	}
	tbs, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	hash := sha3.Sum256(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, signingkey, hash[:])
	if err != nil {
		return nil, err
	}
	rv := &simplehttp.MergePromise{
		TBS:  tbs,
		SigR: r,
		SigS: s,
	}

	return rv, nil
}
func VerifyMergePromise(mp *simplehttp.MergePromise, publickey *ecdsa.PublicKey) (*simplehttp.MergePromiseTBS, error) {
	hash := sha3.Sum256(mp.TBS)
	if !ecdsa.Verify(publickey, hash[:], mp.SigR, mp.SigS) {
		return nil, fmt.Errorf("signature is invalid")
	}
	mptbs := &simplehttp.MergePromiseTBS{}
	err := json.Unmarshal(mp.TBS, &mptbs)
	if err != nil {
		return nil, err
	}
	return mptbs, nil
}
