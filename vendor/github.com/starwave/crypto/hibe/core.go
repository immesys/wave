// Package hibe implements the cryptosystem described in the paper "Hierarchical
// Identity Based Encyprtion with Constant Size Ciphertext" by Boneh, Boyen, and
// Goh.
//
// The algorithms call for us to use a group G that is bilinear, i.e,
// there exists a bilinear map e: G x G -> G2. However, the bn256 library uses
// a slightly different definition of bilinear groups: it defines it as a
// triple of groups (G2, G1, GT) such that there exists a bilinear map
// e: G2 x G1 -> GT. The paper calls this an "asymmetric bilinear group".
//
// It turns out that we are lucky. Both G2 and G1, as implemented in bn256 share
// the same order, and that that order (bn256.Order) happens to be a prime
// number p. Therefore G2 and G1 are both isomorphic to Zp. This is important
// for two reasons. First, the algorithm requires G to be a cyclic group.
// Second, this implies that G2 and G1 are isomorphic to each other. This means
// that as long as we are careful, we can use this library to carry out a
// computation that is logically equivalent to the case where G2 and G1 happen
// to be the same group G.
//
// For simplicity, take G = G2. In other words, choose the G used in Boneh's
// algorithms to be the group G2 provided by bn256.
//
// In order for this work, we need to choose a single isomorphism phi: G2 -> G1
// and stick with it for all operations. Let g1 be the base of G2, and g2 be the
// base of G1, as provided via the APIs of bn256. We define phi as follows:
// phi(g1 ^ a) = g2 ^ a, for all a in Z. This is well defined because G2 is
// isomorphic to Zp, a cyclic group.
//
// What this means is that, if we are working with some x in G to implement the
// algorithm, then we must do so using g1 ^ k in G2 and g2 ^ k in G1, where
// g1 ^ k = x. Using this method, we can emulate the requirements of Boneh's
// algorithm.
//
// Furthermore, note that a marshalled G1 element is 64 bytes, whereas a
// marshalled G2 element is 128 bytes. Therefore, we actually switch the order
// of arguments to the bilinear map e so that marshalled parameters and keys are
// smaller (since otherwise, more elements are passed as the secone argument and
// therefore take up a lot of space). Note that switching the order of arguments
// to a bilinear map (asymmetric or otherwise) maintains bilinearity.
//
// One more thing to note is that the group, as described in the paper, is
// multiplicative, whereas the bn256 library uses additive notation. Keep this
// in mind if you ever need to read through the code.
package hibe

import (
	"crypto/rand"
	"io"
	"math/big"

	"vuvuzela.io/crypto/bn256"
)

// Params represents the system parameters for a hierarchy.
type Params struct {
	G  *bn256.G2
	G1 *bn256.G2
	G2 *bn256.G1
	G3 *bn256.G1
	H  []*bn256.G1

	// Some cached state
	Pairing *bn256.GT
}

// MasterKey represents the key for a hierarchy that can create a key for any
// element.
type MasterKey *bn256.G1

// MaximumDepth returns the maximum depth of the hierarchy. This was specified
// via the "l" argument when Setup was called.
func (params *Params) MaximumDepth() int {
	return len(params.H)
}

// PrivateKey represents a key for an ID in a hierarchy that can decrypt
// messages encrypted with that ID and issue keys for children of that ID in
// the hierarchy.
type PrivateKey struct {
	A0 *bn256.G1
	A1 *bn256.G2
	B  []*bn256.G1
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	A *bn256.GT
	B *bn256.G2
	C *bn256.G1
}

// DepthLeft returns the maximum depth of descendants in the hierarchy whose
// keys can be generated from this one.
func (privkey *PrivateKey) DepthLeft() int {
	return len(privkey.B)
}

// Setup generates the system parameters, (hich may be made visible to an
// adversary. The parameter "l" is the maximum depth that the hierarchy will
// support.
func Setup(random io.Reader, l int) (*Params, MasterKey, error) {
	params := &Params{}
	var err error

	// The algorithm technically needs g to be a generator of G, but since G is
	// isomorphic to Zp, any element in G is technically a generator. So, we
	// just choose a random element.
	_, params.G, err = bn256.RandomG2(random)
	if err != nil {
		return nil, nil, err
	}

	// Choose a random alpha in Zp.
	alpha, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	// Choose g1 = g ^ alpha.
	params.G1 = new(bn256.G2).ScalarMult(params.G, alpha)

	// Randomly choose g2 and g3.
	_, params.G2, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}
	_, params.G3, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}

	// Randomly choose h1 ... hl.
	params.H = make([]*bn256.G1, l, l)
	for i := range params.H {
		_, params.H[i], err = bn256.RandomG1(random)
		if err != nil {
			return nil, nil, err
		}
	}

	// Compute the master key as g2 ^ alpha.
	master := new(bn256.G1).ScalarMult(params.G2, alpha)

	return params, master, nil
}

// KeyGen generates a key for an ID using the master key.
func KeyGen(random io.Reader, params *Params, master MasterKey, id []*big.Int) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth.")
	}

	// Randomly choose r in Zp.
	r, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	product := new(bn256.G1).Set(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		product.Add(product, h)
	}
	product.ScalarMult(product, r)

	key.A0 = new(bn256.G1).Add(master, product)
	key.A1 = new(bn256.G2).ScalarMult(params.G, r)
	key.B = make([]*bn256.G1, l-k)
	for j := 0; j != l-k; j++ {
		key.B[j] = new(bn256.G1).ScalarMult(params.H[k+j], r)
	}

	return key, nil
}

// NonDelegableKeyGenFromMaster generates a key for an ID using the master key.
// The resulting key is not re-randomized, and therefore is not suitable for
// delegation to other entities.
func NonDelegableKeyFromMaster(params *Params, master MasterKey, id []*big.Int) *PrivateKey {
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth.")
	}

	product := new(bn256.G1).Set(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		product.Add(product, h)
	}

	key.A0 = new(bn256.G1).Add(master, product)
	key.A1 = new(bn256.G2).Set(params.G)
	key.B = make([]*bn256.G1, l-k)
	for j := 0; j != l-k; j++ {
		key.B[j] = new(bn256.G1).Set(params.H[k+j])
	}

	return key
}

// QualifyKey generates a key for an ID using the private key of ancestor
// ancestor of ID in the hierarchy. Using a key that does not correspond to
// an ancestor of ID will result in undefined behavior.
func QualifyKey(random io.Reader, params *Params, ancestor *PrivateKey, id []*big.Int) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth")
	}

	// Randomly choose t in Zp
	t, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	product := new(bn256.G1).Set(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		product.Add(product, h)
	}
	product.ScalarMult(product, t)

	key.A0 = new(bn256.G1).Add(ancestor.A0, product)

	newterms := k + ancestor.DepthLeft() - l
	for j := 0; j != newterms; j++ {
		bpower := new(bn256.G1).ScalarMult(ancestor.B[j], id[k-newterms+j])
		key.A0.Add(key.A0, bpower)
	}

	key.A1 = new(bn256.G2).ScalarMult(params.G, t)
	key.A1.Add(ancestor.A1, key.A1)

	key.B = make([]*bn256.G1, l-k)
	for j := 0; j != l-k; j++ {
		key.B[j] = new(bn256.G1).ScalarMult(params.H[k+j], t)
		key.B[j].Add(ancestor.B[j+1], key.B[j])
	}

	return key, nil
}

// NonDelegableKey is like QualifyKey, except that the resulting key should only
// be used for decryption. This is significantly faster than the QualifyKey
// function. However, the output should _not_ be delegated to another
// entity, as it is not properly re-randomized and could leak information about
// the ancestor key.
// QualifyKey generates a key for an ID using the private key of ancestor
// ancestor of ID in the hierarchy. Using a key that does not correspond to
// an ancestor of ID will result in undefined behavior.
func NonDelegableKey(params *Params, ancestor *PrivateKey, id []*big.Int) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth")
	}

	key.A0 = new(bn256.G1).Set(ancestor.A0)

	newterms := k + ancestor.DepthLeft() - l
	for j := 0; j != newterms; j++ {
		bpower := new(bn256.G1).ScalarMult(ancestor.B[j], id[k-newterms+j])
		key.A0.Add(key.A0, bpower)
	}

	key.A1 = ancestor.A1
	key.B = ancestor.B[newterms:]

	return key, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
}

// Encrypt converts the provided message to ciphertext, using the provided ID
// as the public key.
func Encrypt(random io.Reader, params *Params, id []*big.Int, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := &Ciphertext{}
	k := len(id)

	// Randomly choose s in Zp
	s, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}

	ciphertext.A = new(bn256.GT)
	ciphertext.A.ScalarMult(params.Pairing, s)
	ciphertext.A.Add(ciphertext.A, message)

	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)

	ciphertext.C = new(bn256.G1).Set(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		ciphertext.C.Add(ciphertext.C, h)
	}
	ciphertext.C.ScalarMult(ciphertext.C, s)

	return ciphertext, nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(key *PrivateKey, ciphertext *Ciphertext) *bn256.GT {
	plaintext := bn256.Pair(ciphertext.C, key.A1)
	invdenominator := new(bn256.GT).Neg(bn256.Pair(key.A0, ciphertext.B))
	plaintext.Add(plaintext, invdenominator)
	plaintext.Add(ciphertext.A, plaintext)
	return plaintext
}
