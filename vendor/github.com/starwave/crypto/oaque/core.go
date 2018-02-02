// Package oaque implements OAQUE, which is Ordered-Attribute-Qualified
// Encryption. The construction is based on the HIBE construction.
package oaque

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"sync"
	"sync/atomic"

	"vuvuzela.io/crypto/bn256"
)

// Params represents the system parameters for an OAQUE cryptosystem.
type Params struct {
	G  *bn256.G2
	G1 *bn256.G2
	G2 *bn256.G1
	G3 *bn256.G1
	H  []*bn256.G1

	// Some cached state
	Pairing atomic.Value
	// If the pairing is unset, it will be set while holding this mutex
	PairingMutex sync.Mutex
}

// SignatureParams represents additional system parameters for OAQUE signatures.
type SignatureParams struct {
	U0 *bn256.G1
	U1 *bn256.G1
}

// MasterKey represents the key for a hierarchy that can create a key for any
// element.
type MasterKey bn256.G1

// AttributeIndex represents an attribute --- specifically, its index in the
// array of attributes.
type AttributeIndex int

// AttributeList represents a list of attributes. It is map from each set
// attribute (by its index) to the value of that attribute.
//
// Mapping a slot to nil has special meaning when an AttributeList is passed
// to KeyGen, QualifyKey, NonDelegableKeyFromMaster, or NonDelegableKey; the
// slot will remain "free" but will be non-delegable. This can be used to
// create partially delegable keys.
//
// However, a slot should not be mapped to nil when calling
// PrepareAttributeSet(), Encrypt(), or Verify(). Doing so will likely cause
// your program to crash.
type AttributeList map[AttributeIndex]*big.Int

// MaximumDepth returns the number of attributes supported. This was specified
// via the "l" argument when Setup was called.
func (params *Params) NumAttributes() int {
	return len(params.H)
}

// PrivateKey represents a key for an ID in a hierarchy that can decrypt
// messages encrypted with that ID and issue keys for children of that ID in
// the hierarchy.
type PrivateKey struct {
	A0      *bn256.G1
	A1      *bn256.G2
	B       []*bn256.G1
	FreeMap map[AttributeIndex]int
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	A *bn256.GT
	B *bn256.G2
	C *bn256.G1
}

// Signature represents a signature over an integer in Zp.
type Signature struct {
	S1 *bn256.G1
	S2 *bn256.G2
	S3 *bn256.G2
}

// PreparedAttributeList represents an attribute set that has been "prepared"
// for fast encryption or fast verification in a particular OAQUE system.
type PreparedAttributeList bn256.G1

// FreeAttributes returns the indexes of unbound attributes.
func (privkey *PrivateKey) FreeAttributes() []AttributeIndex {
	free := make([]AttributeIndex, len(privkey.FreeMap))
	for idx := range privkey.FreeMap {
		free = append(free, idx)
	}
	return free
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 1 to l-1).
func Setup(random io.Reader, l int) (*Params, *MasterKey, error) {
	params := new(Params)
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

	return params, (*MasterKey)(master), nil
}

// SignatureSetup generates the additional system parameters needed to support
// OAQUE signatures.
func SignatureSetup(random io.Reader) (*SignatureParams, error) {
	params := new(SignatureParams)
	var err error

	_, params.U0, err = bn256.RandomG1(random)
	if err != nil {
		return nil, err
	}

	_, params.U1, err = bn256.RandomG1(random)
	if err != nil {
		return nil, err
	}

	return params, nil
}

// RandomInZp returns an element chosen from Zp uniformly at random, using the
// provided reader as a random number source.
func RandomInZp(random io.Reader) (*big.Int, error) {
	return rand.Int(random, bn256.Order)
}

// KeyGen generates a key for an attribute list using the master key.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. The parameter "r" is an element of Zp. It should
// be chosen uniformly at random, and represents the randomness to use to
// generate the key. If left as nil, it will be generated using a cryptographic
// random number generator.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func KeyGen(r *big.Int, params *Params, master *MasterKey, attrs AttributeList) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(attrs)
	l := len(params.H)

	// Randomly choose r in Zp.
	if r == nil {
		var err error
		r, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	product := new(bn256.G1).Set(params.G3)
	key.B = make([]*bn256.G1, l-k)
	key.FreeMap = make(map[AttributeIndex]int)
	j := 0
	for i, h := range params.H {
		attrIndex := AttributeIndex(i)
		if attr, ok := attrs[attrIndex]; ok {
			if attr != nil {
				hi := new(bn256.G1).ScalarMult(h, attr)
				product.Add(product, hi)
			}
		} else {
			key.B[j] = new(bn256.G1).ScalarMult(h, r)
			key.FreeMap[attrIndex] = j
			j++
		}
	}
	product.ScalarMult(product, r)

	key.A0 = new(bn256.G1).Add((*bn256.G1)(master), product)
	key.A1 = new(bn256.G2).ScalarMult(params.G, r)

	return key, nil
}

// NonDelegableKeyFromMaster is like KeyGen, except that the resulting key should
// only be used for decryption or signing. This is significantly faster than
// the regular KeyGen. However, the output should _not_ be delegated to another
// entity, as it is not properly re-randomized and could leak the master key.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func NonDelegableKeyFromMaster(params *Params, master *MasterKey, attrs AttributeList) *PrivateKey {
	key := &PrivateKey{}
	k := len(attrs)
	l := len(params.H)

	product := new(bn256.G1).Set(params.G3)
	key.B = make([]*bn256.G1, l-k)
	key.FreeMap = make(map[AttributeIndex]int)
	j := 0
	for i, h := range params.H {
		attrIndex := AttributeIndex(i)
		if attr, ok := attrs[attrIndex]; ok {
			if attr != nil {
				hi := new(bn256.G1).ScalarMult(h, attr)
				product.Add(product, hi)
			}
		} else {
			key.B[j] = new(bn256.G1).Set(h)
			key.FreeMap[attrIndex] = j
			j++
		}
	}

	key.A0 = new(bn256.G1).Add((*bn256.G1)(master), product)
	key.A1 = new(bn256.G2).Set(params.G)

	return key
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. The parameter "t" is an element of Zp. It should
// be chosen uniformly at random, and represents the randomness to use to
// generate the new key. If left as nil, it will be generated using Go's
// crypto/rand.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func QualifyKey(t *big.Int, params *Params, qualify *PrivateKey, attrs AttributeList) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(attrs)
	l := len(params.H)

	// Randomly choose t in Zp
	if t == nil {
		var err error
		t, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	key.A0 = new(bn256.G1).Set(qualify.A0)
	product := new(bn256.G1).Set(params.G3)
	key.B = make([]*bn256.G1, l-k)
	key.FreeMap = make(map[AttributeIndex]int)
	j := 0
	for i, h := range params.H {
		attrIndex := AttributeIndex(i)
		if attr, ok := attrs[attrIndex]; ok {
			if attr != nil {
				hi := new(bn256.G1).ScalarMult(h, attr)
				product.Add(product, hi)
				if index, ok := qualify.FreeMap[attrIndex]; ok {
					bi := new(bn256.G1).ScalarMult(qualify.B[index], attr)
					key.A0.Add(key.A0, bi)
				}
			}
		} else {
			key.B[j] = new(bn256.G1).ScalarMult(h, t)
			if bidx, ok := qualify.FreeMap[AttributeIndex(i)]; ok {
				key.B[j].Add(qualify.B[bidx], key.B[j])
				key.FreeMap[attrIndex] = j
				j++
			}
		}
	}
	product.ScalarMult(product, t)

	key.A0.Add(key.A0, product)

	key.A1 = new(bn256.G2).ScalarMult(params.G, t)
	key.A1.Add(qualify.A1, key.A1)

	return key, nil
}

// NonDelegableKey is like QualifyKey, except that the resulting key should only
// be used for decryption or signing. This is significantly faster than the
// QualifyKey function. However, the output should _not_ be delegated to another
// entity, as it is not properly re-randomized and could leak information about
// the parent key.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func NonDelegableKey(params *Params, qualify *PrivateKey, attrs AttributeList) *PrivateKey {
	k := len(attrs)
	l := len(params.H)
	key := &PrivateKey{
		A0:      new(bn256.G1),
		A1:      qualify.A1,
		B:       make([]*bn256.G1, l-k),
		FreeMap: make(map[AttributeIndex]int),
	}

	key.A0.Set(qualify.A0)

	bIndex := 0
	for attrIndex, idx := range qualify.FreeMap {
		if attr, ok := attrs[attrIndex]; ok {
			if attr != nil {
				attrTerm := new(bn256.G1).Set(qualify.B[idx])
				attrTerm.ScalarMult(attrTerm, attr)
				key.A0.Add(key.A0, attrTerm)
			}
		} else {
			key.B[bIndex] = qualify.B[idx]
			key.FreeMap[attrIndex] = bIndex
			bIndex++
		}
	}

	return key
}

// ResampleKey uses the provided private key to sample a new private key with
// the same capability, using the provided randomness t. If t is nil, then the
// new private key is sampled uniformly at random. If delegable is true, the
// new private key can be qualified via QualifyKey or NonDelegableKey, but this
// function takes longer to execute. If delegable is false, the resulting
// private key cannot be used with QualifyKey or NonDelegableKey, but resampling
// is faster.
// Because each private key produces a disjoint distribution of signatures for
// messages, resampling the key before producing a signature allows for
// "anonymous" signature.
func ResampleKey(t *big.Int, params *Params, precomputed *PreparedAttributeList, key *PrivateKey, delegable bool) (*PrivateKey, error) {
	resampled := &PrivateKey{
		A0: new(bn256.G1),
		A1: new(bn256.G2),
	}

	// Randomly choose t in Zp
	if t == nil {
		var err error
		t, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	resampled.A0.ScalarMult((*bn256.G1)(precomputed), t)
	resampled.A0.Add(resampled.A0, key.A0)

	resampled.A1.ScalarMult(params.G, t)
	resampled.A1.Add(resampled.A1, key.A1)

	if delegable {
		resampled.B = make([]*bn256.G1, len(key.B), cap(key.B))
		for attrIndex, bIndex := range key.FreeMap {
			h := new(bn256.G1).ScalarMult(params.H[attrIndex], t)
			h.Add(h, key.B[bIndex])
			resampled.B[bIndex] = h
		}
		resampled.FreeMap = key.FreeMap
	}

	return resampled, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing.Load() == nil {
		params.PairingMutex.Lock()
		if params.Pairing.Load() == nil {
			params.Pairing.Store(bn256.Pair(params.G2, params.G1))
		}
		params.PairingMutex.Unlock()
	}
}

// Encrypt converts the provided message to ciphertext, using the provided ID
// as the public key. The argument "s" is the randomness to use, and should be
// an integer chosen uniformly at random from Zp. If nil, "s" will be generated
// from crypto/rand
func Encrypt(s *big.Int, params *Params, attrs AttributeList, message *bn256.GT) (*Ciphertext, error) {
	return EncryptPrecomputed(s, params, PrepareAttributeSet(params, attrs), message)
}

// PrecomputeAttributeSet performs precomputation for the provided attribute
// list, to speed up future encryption or verification. with that attribute list.
// The returned precomputed result can be safely reused multiple times. This can
// be useful if you are repeatedly encrypting messages or verifying signatures
// with the same attribute list and want to speed things up.
func PrepareAttributeSet(params *Params, attrs AttributeList) *PreparedAttributeList {
	c := new(bn256.G1).Set(params.G3)
	for attrIndex, attr := range attrs {
		h := new(bn256.G1).ScalarMult(params.H[attrIndex], attr)
		c.Add(c, h)
	}
	return (*PreparedAttributeList)(c)
}

// EncryptPrecomputed encrypts the provided message, using the provided
// precomputation to speed up the process.
func EncryptPrecomputed(s *big.Int, params *Params, precomputed *PreparedAttributeList, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := new(Ciphertext)

	// Randomly choose s in Zp
	if s == nil {
		var err error
		s, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	params.Precache()
	pairing := params.Pairing.Load().(*bn256.GT)

	ciphertext.A = new(bn256.GT)
	ciphertext.A.ScalarMult(pairing, s)
	ciphertext.A.Add(ciphertext.A, message)

	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)

	ciphertext.C = new(bn256.G1).ScalarMult((*bn256.G1)(precomputed), s)

	return ciphertext, nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(key *PrivateKey, ciphertext *Ciphertext) *bn256.GT {
	plaintext := bn256.Pair(ciphertext.C, key.A1)
	denominator := bn256.Pair(key.A0, ciphertext.B)
	plaintext.Add(plaintext, denominator.Neg(denominator))
	plaintext.Add(ciphertext.A, plaintext)
	return plaintext
}

// Sign produces a signature for the provided message hash, using the provided
// private key.
func Sign(s *big.Int, params *Params, sigparams *SignatureParams, key *PrivateKey, message *big.Int) (*Signature, error) {
	signature := new(Signature)

	// Randomly choose s in Zp
	if s == nil {
		var err error
		s, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	signature.S1 = new(bn256.G1).ScalarMult(sigparams.U1, message)
	signature.S1.Add(signature.S1, sigparams.U0)
	signature.S1.ScalarMult(signature.S1, s)
	signature.S1.Add(key.A0, signature.S1)

	signature.S2 = key.A1

	signature.S3 = new(bn256.G2).ScalarMult(params.G, s)

	return signature, nil
}

// Verify verifies that the provided signature was produced using an OAQUE
// private key corresponding to the provided attribute set.
func Verify(params *Params, sigparams *SignatureParams, attrs AttributeList, signature *Signature, message *big.Int) bool {
	return VerifyPrecomputed(params, sigparams, PrepareAttributeSet(params, attrs), signature, message)
}

// VerifyPrecomputed verifies the provided signature, using the provided
// precomputation to speed up the process.
func VerifyPrecomputed(params *Params, sigparams *SignatureParams, precomputed *PreparedAttributeList, signature *Signature, message *big.Int) bool {
	lhs := bn256.Pair(signature.S1, params.G)

	params.Precache()
	pairing := params.Pairing.Load().(*bn256.GT)

	rhs2 := bn256.Pair((*bn256.G1)(precomputed), signature.S2)

	mrep := new(bn256.G1).ScalarMult(sigparams.U1, message)
	mrep.Add(sigparams.U0, mrep)
	rhs3 := bn256.Pair(mrep, signature.S3)

	rhs2.Add(pairing, rhs2)
	rhs2.Add(rhs2, rhs3)

	return bytes.Equal(lhs.Marshal(), rhs2.Marshal())
}
