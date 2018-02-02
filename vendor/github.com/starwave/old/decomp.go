package core

import (
	"crypto/rand"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/hibe"
	"vuvuzela.io/crypto/bn256"
)

/* Table management */

// Consider an ID u1/u2/u3/t1/t2/t3, in any order that preserves the relative
// ordering of u1,u2,u3 and t1,t2,t3. To compute the ciphertext for this ID, we
// compute the group element for each component, and multiply them together.
// The group element for each component depends both on the element itself
// (i.e., whether it is a URI component of time component, and its ordering
// relative to other components of the same type) and its position in the final
// ID. The index of the correct group element can be found with the following
// functions.

// URIComponentIndex computes the index of a certain component in the table. M
// is the maximum URI depth, N is the maximum expiry depth, C is the index of
// the URI component, and P is the position of the component in the ID. Given M
// and N, this function returns the index in the table of the group element for
// URI component C at position P in an ID.
//
// The formula is (N+1)*C + (P-C), which simplifies to N*C + P
func URIComponentIndex(m int, n int, c int, p int) int {
	return n*c + p
}

// TimeComponentIndex computes the index of a certain component in the table. M
// is the maximum URI depth, N is the maximum expiry depth, C is the index of
// the Time component, and P is the position of the component in the ID. Given M
// and N, this function returns the index in the table of the group element for
// Time component C at position P in an ID.
//
// The formula is (N+1)*M + (M+1)*C + (P-C), which simplifies M*(N+1+C) + P
func TimeComponentIndex(m int, n int, c int, p int) int {
	return m*(n+1+c) + p
}

/* Ciphertext decomposition */

type DecomposedCiphertext struct {
	A *bn256.GT
	B *bn256.G2

	NumURIComponents  uint8
	NumTimeComponents uint8
	Table             []*bn256.G1
	D                 *bn256.G1
}

// URIComponentElement returns the group element for the particular URI
// component index and ID index.
func (dct *DecomposedCiphertext) URIComponentElement(c URIComponentPosition, p int) *bn256.G1 {
	i := URIComponentIndex(int(dct.NumURIComponents), int(dct.NumTimeComponents), int(c), p)
	return dct.Table[i]
}

// TimeComponentElement returns the group element for the particular URI
// component index and ID index.
func (dct *DecomposedCiphertext) TimeComponentElement(c TimeComponentPosition, p int) *bn256.G1 {
	i := TimeComponentIndex(int(dct.NumURIComponents), int(dct.NumTimeComponents), int(c), p)
	return dct.Table[i]
}

// EncryptDecomposed encrypts an element of GT using HIBE and Ciphertext
// Decomposition.
func EncryptDecomposed(message *bn256.GT, params *hibe.Params, uriPath ID, timePath ID) *DecomposedCiphertext {
	if params.Pairing == nil {
		panic("Pairing must be Precached before calling EncryptDecomposed()")
	}

	// Randomly choose s in Zp
	s, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}

	ciphertext := new(DecomposedCiphertext)

	ciphertext.A = new(bn256.GT)
	ciphertext.A.ScalarMult(params.Pairing, s)
	ciphertext.A.Add(ciphertext.A, message)

	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)

	ciphertext.D = new(bn256.G1).ScalarMult(params.G3, s)

	m := len(uriPath)
	n := len(timePath)
	hCacheSize := m + n
	tableSize := m + n + ((m * n) << 1)

	uriHashed := uriPath.HashToZp()
	timeHashed := timePath.HashToZp()

	ciphertext.NumURIComponents = uint8(m)
	ciphertext.NumTimeComponents = uint8(n)

	ciphertext.Table = make([]*bn256.G1, tableSize, tableSize)

	hCache := make([]*bn256.G1, m+n)
	for i := 0; i != hCacheSize; i++ {
		hCache[i] = new(bn256.G1).ScalarMult(params.H[i], s)
	}

	for j, uriComponentHash := range uriHashed {
		// pos varies over all positions in the final ID at which this URI
		// component could be.
		for pos := j; pos != j+n+1; pos++ {
			index := URIComponentIndex(m, n, j, pos)
			ciphertext.Table[index] = new(bn256.G1)
			ciphertext.Table[index].ScalarMult(hCache[pos], uriComponentHash)
		}
	}

	for j, timeComponentHash := range timeHashed {
		// pos varies over all positions in the final ID at which this time
		// component could be.
		for pos := j; pos != j+m+1; pos++ {
			index := TimeComponentIndex(m, n, j, pos)
			ciphertext.Table[index] = new(bn256.G1)
			ciphertext.Table[index].ScalarMult(hCache[pos], timeComponentHash)
		}
	}

	return ciphertext
}

// AssembleCiphertext computes the ciphertext of the message encrypted under
// the specified ID.
func AssembleCiphertext(ciphertext *DecomposedCiphertext, id ID) *hibe.Ciphertext {
	thirdElement := new(bn256.G1).ScalarMult(ciphertext.D, big.NewInt(1))

	var uriRelPos URIComponentPosition = 0
	var timeRelPos TimeComponentPosition = 0
	for pos, idComponent := range id {
		var elem *bn256.G1
		if idComponent.Type() == URIComponentType {
			elem = ciphertext.URIComponentElement(uriRelPos, pos)
			uriRelPos++
		} else {
			elem = ciphertext.TimeComponentElement(timeRelPos, pos)
			timeRelPos++
		}
		thirdElement.Add(thirdElement, elem)
	}

	return &hibe.Ciphertext{
		A: ciphertext.A,
		B: ciphertext.B,
		C: thirdElement,
	}
}

// DecryptDecomposed decrypts the ciphertext and returns the plaintext element
// of GT.
func DecryptDecomposed(ciphertext *DecomposedCiphertext, id ID, key *hibe.PrivateKey) *bn256.GT {
	hibeCiphertext := AssembleCiphertext(ciphertext, id)
	if hibeCiphertext == nil {
		return nil
	}

	return hibe.Decrypt(key, hibeCiphertext)
}
