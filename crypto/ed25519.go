// This file is part of BOSSWAVE.
//
// BOSSWAVE is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// BOSSWAVE is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with BOSSWAVE.  If not, see <http://www.gnu.org/licenses/>.
//
// Copyright © 2015 Michael Andersen <m.andersen@cs.berkeley.edu>

package crypto

// #cgo linux,amd64 CFLAGS: -O3
// #cgo linux,amd64 LDFLAGS: -lssl -lcrypto
// #cgo !linux !amd64 CFLAGS: -O2 -DWINSUPPORT
// #include "ed25519.h"
// #include <string.h>
// #include <stdint.h>
import "C"

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"sync"
	"unsafe"

	"golang.org/x/crypto/curve25519"
)

//These functions are used on windows by the C so we don't have to link to openSSL

var hashCtxLock sync.Mutex
var hashCtxMap map[uint32]hash.Hash
var hashCtxIdx uint32

func init() {
	hashCtxMap = make(map[uint32]hash.Hash)
}

//export HashInit
func HashInit(ctx *C.uint32_t) {
	hashCtxLock.Lock()
	idx := hashCtxIdx
	hashCtxIdx++
	hashCtxMap[idx] = sha512.New()
	hashCtxLock.Unlock()
	*ctx = C.uint32_t(idx)
}

//export HashUpdate
func HashUpdate(ctx *C.uint32_t, in *C.uint8_t, inlen C.size_t) {
	hashCtxLock.Lock()
	h := hashCtxMap[uint32(*ctx)]
	hashCtxLock.Unlock()
	//Not that I care about windows performance, but this is an
	//unecessary copy
	h.Write(C.GoBytes(unsafe.Pointer(in), C.int(inlen)))
}

//export HashFinal
func HashFinal(ctx *C.uint32_t, hash *C.uint8_t) {
	hashCtxLock.Lock()
	h := hashCtxMap[uint32(*ctx)]
	delete(hashCtxMap, uint32(*ctx))
	hashCtxLock.Unlock()
	rv := h.Sum(nil)
	C.memcpy(unsafe.Pointer(hash), unsafe.Pointer(&rv[0]), 64)
}

//export Hash
func Hash(hash *C.uint8_t, in *C.uint8_t, inlen C.size_t) {
	rv := sha512.Sum512(C.GoBytes(unsafe.Pointer(in), C.int(inlen)))
	C.memcpy(unsafe.Pointer(hash), unsafe.Pointer(&rv[0]), 64)
}

//export RandomBytes
func RandomBytes(dest *C.uint8_t, ln C.size_t) {
	rv := make([]byte, ln)
	rand.Read(rv)
	C.memcpy(unsafe.Pointer(dest), unsafe.Pointer(&rv[0]), ln)
}

//SignVector will generate a signature on the arguments, in order
//and return it
func SignVector(sk []byte, vk []byte, into []byte, vec ...[]byte) {
	if len(into) != 64 {
		panic("Into must be exactly 64 bytes long")
	}
	lens := make([]C.size_t, len(vec))
	for i, v := range vec {
		lens[i] = C.size_t(len(v))
	}
	//From SO user jimt
	var b *C.char
	ptrSize := unsafe.Sizeof(b)

	// Allocate the char** list.
	ptr := C.malloc(C.size_t(len(vec)) * C.size_t(ptrSize))
	defer C.free(ptr)

	// Assign each byte slice to its appropriate offset.
	for i := 0; i < len(vec); i++ {
		element := (**C.char)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*ptrSize))
		*element = (*C.char)(unsafe.Pointer(&vec[i][0]))
	}

	C.ed25519_sign_vector((**C.uchar)(ptr),
		(*C.size_t)(unsafe.Pointer(&lens[0])),
		(C.size_t)(len(vec)),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
		(*C.uchar)(unsafe.Pointer(&vk[0])),
		(*C.uchar)(unsafe.Pointer(&into[0])))
}

func SignBlob(sk []byte, vk []byte, into []byte, blob []byte) {
	if len(into) != 64 {
		panic("into must be exactly 64 bytes long")
	}
	C.ed25519_sign((*C.uchar)(unsafe.Pointer(&blob[0])),
		(C.size_t)(len(blob)),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
		(*C.uchar)(unsafe.Pointer(&vk[0])),
		(*C.uchar)(unsafe.Pointer(&into[0])))
}

//VerifyBlob returns true if the sig is ok, false otherwise
func VerifyBlob(vk []byte, sig []byte, blob []byte) bool {
	rv := C.ed25519_sign_open((*C.uchar)(unsafe.Pointer(&blob[0])),
		(C.size_t)(len(blob)),
		(*C.uchar)(unsafe.Pointer(&vk[0])),
		(*C.uchar)(unsafe.Pointer(&sig[0])))
	return rv == 0
}

func VKforSK(sk []byte) []byte {
	vk := make([]byte, 32)
	C.ed25519_publickey((*C.uchar)(unsafe.Pointer(&sk[0])),
		(*C.uchar)(unsafe.Pointer(&vk[0])))
	return vk
}

func ConvertEd25519SKtoCurve25519SK(sk []byte) []byte {
	rv := make([]byte, 64)
	C.bw_extsk((*C.uchar)(unsafe.Pointer(&rv[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))
	return rv[:32]
}
func ConvertEd25519VKtoCurve25519PK(vk []byte) []byte {
	rv := make([]byte, 32)
	C.bw_ed2curvePK((*C.uchar)(unsafe.Pointer(&rv[0])), (*C.uchar)(unsafe.Pointer(&vk[0])))
	return rv
}
func Curve25519PrivToCurve25519Pub(priv []byte) []byte {
	rv := make([]byte, 32)
	C.curved25519_scalarmult_basepoint((*C.uchar)(unsafe.Pointer(&rv[0])), (*C.uchar)(unsafe.Pointer(&priv[0])))
	return rv
}

func Ed25519CalcSecret(ourSK []byte, theirVK []byte) []byte {
	if len(ourSK) != 32 || len(theirVK) != 32 {
		fmt.Printf("sk is %d vk is %d\n", len(ourSK), len(theirVK))
		panic("bad sk/vk len")
	}
	priva := [64]byte{}
	C.bw_extsk((*C.uchar)(unsafe.Pointer(&priva[0])), (*C.uchar)(unsafe.Pointer(&ourSK[0])))
	puba := [32]byte{}
	C.bw_ed2curvePK((*C.uchar)(unsafe.Pointer(&puba[0])), (*C.uchar)(unsafe.Pointer(&theirVK[0])))
	rv := [32]byte{}
	curve25519.ScalarMult(&rv, (*[32]byte)(unsafe.Pointer(&priva)), &puba)
	return rv[:]
}

// func SKExt2(sk []byte) []byte {
// 	rv := make([]byte, 64)
// 	C.bw_extsk2((*C.uchar)(unsafe.Pointer(&rv[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))
// 	return rv
// }
func SMMB(sk []byte) []byte {
	rv := make([]byte, 32)
	C.curved25519_scalarmult_basepoint((*C.uchar)(unsafe.Pointer(&rv[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))
	return rv
}
func GenerateKeypair() (sk []byte, vk []byte) {
	sk = make([]byte, 32)
	vk = make([]byte, 32)
	for {
		C.bw_generate_keypair((*C.uchar)(unsafe.Pointer(&sk[0])),
			(*C.uchar)(unsafe.Pointer(&vk[0])))
		if FmtKey(vk)[0] != '-' {
			return
		}
	}
}

func CheckKeypair(sk []byte, vk []byte) bool {
	blob := make([]byte, 128)
	rand.Read(blob)
	sig := make([]byte, 64)
	SignBlob(sk, vk, sig, blob)
	return VerifyBlob(vk, sig, blob)
}

func FmtKey(key []byte) string {
	return base64.URLEncoding.EncodeToString(key)
}

func UnFmtKey(key string) ([]byte, error) {
	rv, err := base64.URLEncoding.DecodeString(key)
	if len(rv) != 32 {
		return nil, errors.New("Invalid length")
	}
	return rv, err
}

func FmtSig(sig []byte) string {
	return base64.URLEncoding.EncodeToString(sig)
}
func UnFmtSig(sig string) ([]byte, error) {
	rv, err := base64.URLEncoding.DecodeString(sig)
	if len(rv) != 64 {
		return nil, errors.New("Invalid length")
	}
	return rv, err
}

func FmtHash(hash []byte) string {
	return base64.URLEncoding.EncodeToString(hash)
}
func UnFmtHash(hash string) ([]byte, error) {
	rv, err := base64.URLEncoding.DecodeString(hash)
	if len(rv) != 32 {
		return nil, errors.New("Invalid length")
	}
	return rv, err
}
