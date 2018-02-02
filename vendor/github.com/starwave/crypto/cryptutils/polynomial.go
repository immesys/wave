package cryptutils

import (
	"crypto/rand"
	"io"
	"math/big"
)

// Polynomial represents a polynomial. The first element of the slice is the
// coefficient of the term of highest degree, and the remaining elements are
// the coefficients of the terms of lower degrees.
type Polynomial []*big.Int

// Return an "empty" (all coefficients are nil) polynomial with enough
// coefficients with the specified degree.
func EmptyPolynomial(degree int) Polynomial {
	return make(Polynomial, degree+1)
}

// ZeroFill fills in all "nil" coefficients of the polynomial with 0.
func (p Polynomial) ZeroFill(n *big.Int) {
	for i, b := range p {
		if b == nil {
			p[i] = new(big.Int)
		}
	}
}

// RandomFill fills in all "nil" coefficients of the polynomial with a
// randomly chosen integer in [0, N).
func (p Polynomial) RandomFill(random io.Reader, n *big.Int) error {
	for i, b := range p {
		if b == nil {
			var err error
			p[i], err = rand.Int(random, n)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// EvalMod evaluates the polynomial at X, modulo N. It uses Horner's method to
// evaluate the polynomial. See https://en.wikipedia.org/wiki/Horner%27s_method.
func (p Polynomial) EvalMod(x *big.Int, n *big.Int) *big.Int {
	ret := new(big.Int)
	for _, b := range p {
		ret.Mul(ret, x)
		ret.Add(ret, b)
		ret.Mod(ret, n)
	}
	return ret
}
