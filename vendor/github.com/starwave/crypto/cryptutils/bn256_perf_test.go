package cryptutils

import (
	"crypto/rand"
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

func BenchmarkG1Add(b *testing.B) {
	b.StopTimer()

	_, g, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, h, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		g.Add(g, h)
	}
}

func BenchmarkG2Add(b *testing.B) {
	b.StopTimer()

	_, g, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, h, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		g.Add(g, h)
	}
}

func BenchmarkGTAdd(b *testing.B) {
	b.StopTimer()

	_, g1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, g2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	g := bn256.Pair(g1, g2)

	_, h1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	_, h2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	h := bn256.Pair(h1, h2)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		g.Add(g, h)
	}
}

func BenchmarkG1ScalarMult(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		_, g, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		g.ScalarMult(g, s)
		b.StopTimer()
	}
}

func BenchmarkG2ScalarMult(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		_, g, err := bn256.RandomG2(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		g.ScalarMult(g, s)
		b.StopTimer()
	}
}

func BenchmarkGTScalarMult(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		_, g1, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		_, g2, err := bn256.RandomG2(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		g := bn256.Pair(g1, g2)

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		g.ScalarMult(g, s)
		b.StopTimer()
	}
}

func BenchmarkPair(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		_, g1, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		_, g2, err := bn256.RandomG2(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		bn256.Pair(g1, g2)
		b.StopTimer()
	}
}

func BenchmarkZpInverse(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		r, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		r.ModInverse(r, bn256.Order)
		b.StopTimer()
	}
}

func BenchmarkZpAdd(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		r, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		t := new(big.Int)

		b.StartTimer()
		t.Add(r, s)
		b.StopTimer()
	}
}

func BenchmarkZpShift(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		r, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, big.NewInt(64))
		if err != nil {
			b.Fatal(err)
		}

		var suint uint = uint(s.Uint64())

		t := new(big.Int)

		b.StartTimer()
		t.Rsh(r, suint)
		b.StopTimer()
	}
}

func BenchmarkZpMul(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		r, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		t := new(big.Int)

		b.StartTimer()
		t.Mul(r, s)
		b.StopTimer()
	}
}

func BenchmarkZpMod(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		r, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		s, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			b.Fatal(err)
		}

		t := new(big.Int)
		t.Mul(r, s)

		b.StartTimer()
		t.Mod(t, bn256.Order)
		b.StopTimer()
	}
}
