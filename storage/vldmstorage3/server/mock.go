package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/immesys/wave/storage/simplehttp"
	"golang.org/x/crypto/sha3"
)

var auditorSKString = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDtMjphAWPVtYVa06fbMr41WwtOm7FhHRdK4sMZOeHhooAoGCCqGSM49
AwEHoUQDQgAEjxdbNOQuEkIhfN61raSYgijjygMfuVBgJsnNrDbraLaHGzbbrYX1
BoDm9BomJHSSQpeOYTabcdQ9Jy9n8v45oA==
-----END EC PRIVATE KEY-----`

var auditorPKString = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjxdbNOQuEkIhfN61raSYgijjygMf
uVBgJsnNrDbraLaHGzbbrYX1BoDm9BomJHSSQpeOYTabcdQ9Jy9n8v45oA==
-----END PUBLIC KEY-----`

var auditorSK *ecdsa.PrivateKey

func init() {
	k, err := ParsePrivateKey([]byte(auditorSKString))
	if err != nil {
		panic(err)
	}
	auditorSK = k
}

func SignMapRoot(id string, smr []byte) (timestamp int64, r *big.Int, s *big.Int, err error) {
	//The timestamp should be the insert time of the latest log entry that was processed
	timestamp = time.Now().UnixNano() / 1e6
	h := sha3.New256()
	h.Write(smr)
	h.Write([]byte(fmt.Sprintf("%d", timestamp)))
	d := h.Sum(nil)
	r, s, err = ecdsa.Sign(rand.Reader, auditorSK, d[:])
	return
}

func SignMergePromise(id string, mp *simplehttp.MergePromise) (timestamp int64, r *big.Int, s *big.Int, err error) {
	timestamp = time.Now().UnixNano() / 1e6
	h := sha3.New256()
	h.Write(mp.TBS)
	h.Write(mp.SigR.Bytes())
	h.Write(mp.SigS.Bytes())
	h.Write([]byte(fmt.Sprintf("%d", timestamp)))
	d := h.Sum(nil)
	r, s, err = ecdsa.Sign(rand.Reader, auditorSK, d[:])
	return
}
