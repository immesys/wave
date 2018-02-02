package cryptutils

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/sha3"
	"vuvuzela.io/crypto/bn256"
)

// HashToZp hashes a byte slice to an integer in Zp*.
func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
	bigint.Add(bigint, big.NewInt(1))
	return bigint
}

// gtBase is e(g1, g2) where g1 and g2 are the base generators of G2 and G1
var gtBase *bn256.GT

// HashToGT hashes a byte slice to a group element in GT.
func HashToGT(bytestring []byte) *bn256.GT {
	if gtBase == nil {
		gtBase = bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
			new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	}
	return new(bn256.GT).ScalarMult(gtBase, HashToZp(bytestring))
}

// GTToSecretKey hashes an element in group GT to get a secret key. The secret
// key is written into the provided slice (which can be of any length, but
// remember that there are only 32 bytes of entropy in the element of GT).
// Returns the provided slice
func GTToSecretKey(gt *bn256.GT, sk []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(gt.Marshal())
	shake.Read(sk)
	return sk
}

// GenerateKey generates a random key, and an element in GT that hashes to that
// key. The key is written to the provided slice, and that same slice is
// returned. Note that, while the slice can be of any length, there are only
// 32 bytes of entropy in an element in GT.
func GenerateKey(sk []byte) ([]byte, *bn256.GT) {
	var randomness [32]byte
	_, err := rand.Read(randomness[:])
	if err != nil {
		panic(err)
	}
	var randomGT = HashToGT(randomness[:])
	GTToSecretKey(randomGT, sk)

	return sk, randomGT
}
