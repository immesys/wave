// Package lukpabe implements Large-Universe Key-Policy Attribute-Based
// Encryption. The construction is described in Section 5 of the paper
// "Attribute-Based Encryption for Fined-Grained Access Control of Encrypted
// Data" by Goyal, Pandey, Sahai, and Waters.
package lukpabe

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"vuvuzela.io/crypto/bn256"
)

// Params represents the system parameters for an LU KP-ABE cryptosystem.
type Params struct {
	G1 *bn256.G2
	G2 *bn256.G1
	Ts []*bn256.G1

	// Some cached state
	Pairing      *bn256.GT
	InverseTable []*big.Int
}

// MasterKey represents the key that can generate a private key for any access
// tree.
type MasterKey *big.Int

// AttributeSet represents a set of attributes. Each attribute is an integer in
// Zp*.
type AttributeSet []*big.Int

func (as AttributeSet) IndexOf(attr *big.Int) int {
	for i, ei := range as {
		if attr.Cmp(ei) == 0 {
			return i
		}
	}
	return -1
}

// AccessNode represents a node of an access tree.
type AccessNode interface {
	IsLeaf() bool
	Threshold() int
	Children() []AccessNode
	Attribute() *big.Int
	Index() int

	AsGate() *AccessGate
	AsLeaf() *AccessLeaf

	Clone() AccessNode
}

// AccessGate represents an internal node of an access tree.
type AccessGate struct {
	Thresh int
	Inputs []AccessNode
}

func (ag *AccessGate) IsLeaf() bool {
	return false
}

func (ag *AccessGate) Threshold() int {
	return ag.Thresh
}

func (ag *AccessGate) Children() []AccessNode {
	return ag.Inputs
}

func (ag *AccessGate) Attribute() *big.Int {
	panic("Not a leaf node")
}

func (ag *AccessGate) Index() int {
	panic("Not a leaf node")
}

func (ag *AccessGate) AsGate() *AccessGate {
	return ag
}

func (ag *AccessGate) AsLeaf() *AccessLeaf {
	panic("Not a leaf node")
}

func (ag *AccessGate) Clone() AccessNode {
	clone := &AccessGate{
		Thresh: ag.Thresh,
		Inputs: make([]AccessNode, len(ag.Inputs)),
	}
	for i, input := range ag.Inputs {
		clone.Inputs[i] = input.Clone()
	}
	return clone
}

// AccessLeaf represents a leaf node of an access tree.
type AccessLeaf struct {
	Attr *big.Int

	// Private-Key-Specific Information, set by KeyGen
	PrivateKeyIndex int
}

func (al *AccessLeaf) IsLeaf() bool {
	return true
}

func (al *AccessLeaf) Threshold() int {
	panic("Not an internal node")
}

func (al *AccessLeaf) Children() []AccessNode {
	panic("Not an internal node")
}

func (al *AccessLeaf) Attribute() *big.Int {
	return al.Attr
}

func (al *AccessLeaf) Index() int {
	return al.PrivateKeyIndex
}

func (al *AccessLeaf) AsGate() *AccessGate {
	panic("Not an internal node")
}

func (al *AccessLeaf) AsLeaf() *AccessLeaf {
	return al
}

func (al *AccessLeaf) Clone() AccessNode {
	return &AccessLeaf{
		Attr:            new(big.Int).Set(al.Attr),
		PrivateKeyIndex: al.PrivateKeyIndex,
	}
}

// PrivateKey represents a private key for an access tree.
type PrivateKey struct {
	D    []*bn256.G1
	R    []*bn256.G2
	Tree AccessNode
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	E1    *bn256.GT
	E2    *bn256.G2
	Es    []*bn256.G1
	Gamma AttributeSet
}

// RandomInZp returns an element chosen from Zp uniformly at random, using the
// provided reader as a random number source.
func RandomInZp(random io.Reader) (*big.Int, error) {
	return rand.Int(random, bn256.Order)
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "n" is the maximum number of attributes under
// which a message may be encrypted.
func Setup(random io.Reader, n int) (*Params, MasterKey, error) {
	params := new(Params)

	var err error
	var y *big.Int
	y, params.G1, err = bn256.RandomG2(random)
	if err != nil {
		return nil, nil, err
	}

	_, params.G2, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}

	params.Ts = make([]*bn256.G1, n+1)
	for i := range params.Ts {
		_, params.Ts[i], err = bn256.RandomG1(random)
		if err != nil {
			return nil, nil, err
		}
	}

	return params, y, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
	if params.InverseTable == nil {
		params.InverseTable = make([]*big.Int, 2*len(params.Ts)-1)
		n := len(params.Ts) - 1
		for k := range params.InverseTable {
			iMinusJ := big.NewInt(int64(k - n))
			params.InverseTable[k] = iMinusJ.ModInverse(iMinusJ, bn256.Order)
		}
	}
}

// KeyGenNode is a recursive helper function for KeyGen.
func KeyGenNode(random io.Reader, params *Params, key *PrivateKey, q0 *big.Int, node AccessNode) error {
	if node.IsLeaf() {
		// Compute the D and R for this leaf
		rnd, err := RandomInZp(random)
		if err != nil {
			return err
		}

		d := new(bn256.G1).ScalarMult(params.G2, q0)
		ti := params.T(node.Attribute())
		d.Add(d, ti.ScalarMult(ti, rnd))

		r := new(bn256.G2).ScalarBaseMult(rnd)

		key.D = append(key.D, d)
		key.R = append(key.R, r)

		node.AsLeaf().PrivateKeyIndex = len(key.D)
	} else {
		// Decide on a polynomial for this node
		poly := cryptutils.EmptyPolynomial(node.Threshold() - 1)
		poly[len(poly)-1] = q0
		poly.RandomFill(random, bn256.Order)

		for j, child := range node.Children() {
			i := j + 1
			qi := poly.EvalMod(big.NewInt(int64(i)), bn256.Order)
			err := KeyGenNode(random, params, key, qi, child)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// KeyGen generates a private key for the specified access tree, using the
// master key. It traverses the tree, setting the correct AccessIndex for the
// tree, to match this private key.
func KeyGen(random io.Reader, params *Params, master MasterKey, tree AccessNode) (*PrivateKey, error) {
	key := &PrivateKey{
		D:    []*bn256.G1{},
		R:    []*bn256.G2{},
		Tree: tree,
	}
	params.Precache()
	err := KeyGenNode(random, params, key, (*big.Int)(master), tree)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// T implements the function T for a cryptosystem, as described in the paper.
// According to the paper, if we are willing to accept random oracles, then we
// can replace this with a hash function.
func (params *Params) T(x *big.Int) *bn256.G1 {
	n := len(params.Ts) - 1

	// Compute g2 ^ (X^n)
	exp := new(big.Int).Exp(x, big.NewInt(int64(n)), bn256.Order)
	ret := new(bn256.G1).ScalarMult(params.G2, exp)

	for i, t := range params.Ts {
		// Compute Lagrange Coefficient for i, {1, ..., n + 1}
		lagrange := big.NewInt(1)
		for j := range params.Ts {
			if j != i {
				jInt := big.NewInt(int64(j))
				lagrange.Mul(lagrange, jInt.Sub(x, jInt))
				lagrange.Mul(lagrange, params.InverseTable[i-j+n])
				lagrange.Mod(lagrange, bn256.Order)
			}
		}

		ret.Add(ret, new(bn256.G1).ScalarMult(t, lagrange))
	}

	return ret
}

// Encrypt converts the provided message to ciphertext, under the specified
// attribute set. The argument "s" is the randomness to use; if set to nil,
// it is generated using crypto/rand.
func Encrypt(s *big.Int, params *Params, attrs AttributeSet, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := new(Ciphertext)

	if s == nil {
		var err error
		s, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	params.Precache()

	ciphertext.E1 = new(bn256.GT).ScalarMult(params.Pairing, s)
	ciphertext.E1.Add(message, ciphertext.E1)

	ciphertext.E2 = new(bn256.G2).ScalarBaseMult(s)

	ciphertext.Es = make([]*bn256.G1, len(attrs))
	for index, i := range attrs {
		ti := params.T(i)
		ciphertext.Es[index] = ti.ScalarMult(ti, s)
	}

	ciphertext.Gamma = attrs

	return ciphertext, nil
}

// DecryptNode is a recursive helper function for Decrypt.
func DecryptNode(key *PrivateKey, ciphertext *Ciphertext, node AccessNode) *bn256.GT {
	if node.IsLeaf() {
		index := ciphertext.Gamma.IndexOf(node.Attribute())
		if index == -1 {
			return nil
		}

		x := node.Index() - 1
		power := bn256.Pair(key.D[x], ciphertext.E2)
		denominator := bn256.Pair(ciphertext.Es[index], key.R[x])
		power.Add(power, denominator.Neg(denominator))
		return power
	}

	toDecrypt := node.Threshold()
	f := make([]*bn256.GT, 0, toDecrypt)
	s := make([]int, 0, toDecrypt)
	for i, child := range node.Children() {
		if child != nil {
			q0 := DecryptNode(key, ciphertext, child)
			if q0 != nil {
				f = append(f, q0)
				s = append(s, i+1)

				if len(f) == toDecrypt {
					break
				}
			}
		}
	}

	if len(f) != toDecrypt {
		return nil
	}

	// Modular inverses are a bit expensive, so we precompute them and reuse
	inverses := make([]*big.Int, 2*toDecrypt-1)
	for i := range inverses {
		inv := big.NewInt(int64(i - toDecrypt + 1))
		inverses[i] = inv.ModInverse(inv, bn256.Order)
	}

	for k, fz := range f {
		i := s[k]

		// Compute the Lagrange coefficient, evaluated at x = 0
		lagrange := big.NewInt(1)
		for m := 0; m != len(s); m++ {
			j := s[m]
			if j != i {
				lagrange.Mul(lagrange, big.NewInt(int64(-j)))
				lagrange.Mul(lagrange, inverses[i-j+toDecrypt-1])
				lagrange.Mod(lagrange, bn256.Order)
			}
		}
		fz.ScalarMult(fz, lagrange)
	}

	power := f[0]
	for i := 1; i != len(f); i++ {
		power.Add(power, f[i])
	}

	return power
}

// DecryptNodeURI uses optimizations specific to STARWAVE's access trees. The
// access tree is a single gate with many leaves, the first Threshold leaves
// always work.
func DecryptNodeURI(params *Params, key *PrivateKey, ciphertext *Ciphertext, node AccessNode) *bn256.GT {
	lagranges := make([]*big.Int, node.Threshold())

	for k := range lagranges {
		i := k + 1

		// Compute the Lagrange coefficient, evaluated at x = 0
		lagrange := big.NewInt(1)
		for m := 0; m != node.Threshold(); m++ {
			j := m + 1
			if j != i {
				lagrange.Mul(lagrange, big.NewInt(int64(-j)))
				lagrange.Mul(lagrange, params.InverseTable[i-j+len(params.Ts)-1])
				lagrange.Mod(lagrange, bn256.Order)
			}
		}

		lagranges[k] = lagrange
	}

	dxPowers := make([]*bn256.G1, node.Threshold())
	denominators := make([]*bn256.GT, node.Threshold())
	for i, child := range node.Children() {
		leaf := child.AsLeaf()

		x := leaf.Index() - 1

		dxPowers[i] = new(bn256.G1).ScalarMult(key.D[x], lagranges[i])
		denominators[i] = bn256.Pair(new(bn256.G1).ScalarMult(ciphertext.Es[i], lagranges[i]), key.R[x])
	}

	dxPowerProduct := dxPowers[0]
	for i := 1; i != len(dxPowers); i++ {
		dxPowerProduct.Add(dxPowerProduct, dxPowers[i])
	}
	numerator := bn256.Pair(dxPowerProduct, ciphertext.E2)
	denominator := denominators[0]
	for i := 1; i != len(denominators); i++ {
		denominator.Add(denominator, denominators[i])
	}

	return numerator.Add(numerator, denominator.Neg(denominator))
}

// PlanDecryption is a function that plans the evaluation of an access tree,
// in order to decrypt a certain ciphertext. For each node in the access tree,
// this function sets some of its children to "nil" if those children should not
// be evaluated in order to perform the decryption (i.e., the pairings at the
// leaves of those subtrees need not be computed). The goal is to include as
// few leaves as possible in the remaining tree, such that the output is still
// 1. That way, we would minimize the number of pairings computed, while still
// successfully decrypting the ciphertext.
// If the provided attributes satisfy the access tree, then the function sets
// "unused" children to nil, and return true. If the provided attributes do not
// satisfy the access tree, then the function returns false, and the state of
// the access tree is undefined (in the current implementation, the top-level
// node will have all of its children set to nil, but this is subject to change
// if this function is ever revised).
// Abstractly, given a circuit with threshold gates, we want to find the setting
// of leaves that satisfies the circuit, and has the fewest number of leaves
// set. Alternatively, we can think of this problem as boolean satisfiability
// of an AND-OR circuit, where our objective is to find the solution with the
// fewest number of inputs set to 1. (Note that if we restrict boolean
// satisfiability to AND and OR gates, or more generally, to threshold gates,
// then setting all inputs to 1 will be a solution if one exists.)
// The solution that I have implemented here is not optimal in general, but I
// think it is optimal for the access trees we will need for STARWAVE. I
// suspect that finding a generally optimal solution is an NP-complete problem.
func PlanDecryption(plan AccessNode, attrs AttributeSet) bool {
	if plan.IsLeaf() {
		return attrs.IndexOf(plan.Attribute()) != -1
	}

	toSatisfy := plan.Threshold()
	for i, child := range plan.Children() {
		if toSatisfy == 0 {
			plan.AsGate().Inputs[i] = nil
		} else {
			satisfiable := PlanDecryption(child, attrs)
			if satisfiable {
				toSatisfy--
			}
		}
	}
	return toSatisfy == 0
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key. A custom plan for decryption may be passed in, to
// speed things up. The plan argument may also be set to nil, in which case a
// plan is automatically generated and returned.
func Decrypt(key *PrivateKey, ciphertext *Ciphertext, plan AccessNode) (*bn256.GT, AccessNode) {
	if plan == nil {
		plan = key.Tree.Clone()
		decryptable := PlanDecryption(plan, ciphertext.Gamma)
		if !decryptable {
			return nil, nil
		}
	}
	power := DecryptNode(key, ciphertext, plan)
	return new(bn256.GT).Add(ciphertext.E1, power.Neg(power)), plan
}

// DecryptSpecific is a version of Decrypt, with optimizations specific to the
// case where the access tree consists of a single gate, where the first
// "Threshold" inputs evaluate to true.
func DecryptSpecific(params *Params, key *PrivateKey, ciphertext *Ciphertext) *bn256.GT {
	params.Precache()
	power := DecryptNodeURI(params, key, ciphertext, key.Tree)
	return new(bn256.GT).Add(ciphertext.E1, power.Neg(power))
}
