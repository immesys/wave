package cryptutils

import (
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

func IDToInts(id []string) []*big.Int {
	ints := make([]*big.Int, len(id))
	for i, component := range id {
		ints[i] = HashToZp([]byte(component))
	}
	return ints
}

func TestHashID(t *testing.T) {
	idints := IDToInts([]string{"a", "b", "c"})
	for _, idint := range idints {
		if idint.Cmp(bn256.Order) != -1 || idint.Cmp(big.NewInt(0)) != 1 {
			t.Fatal("ID components are not in Zp*")
		}
	}
}
