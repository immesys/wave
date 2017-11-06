package crypto

import (
	"crypto/rand"
	"testing"
)

/*
OpenSSL is used for generating random numbers (not in the hotpath) and
for the sha512 hash (hotpath). Benchmarking the hash performance over
a bunch of difference message sizes is important for determining if
openSSL is even worth using. On windows we don't even have a choice
because its really hard to compile and statically link in

Winsupport NN=256 M=512KB
BenchmarkSign	       1	1041205923 ns/op (4076uS/sig)
BenchmarkVerify	     2	 534121463 ns/op (2086uS/ver)

OpenSSL NN=256 M=512KB
BenchmarkSign	       1	1770249853 ns/op (6915uS/sig)
BenchmarkVerify	     3	 540462163 ns/op (2111uS/ver)

OpenSSL NN=256 M=16KB
BenchmarkSign	    2000	  40166303 ns/op (156uS/sig)
BenchmarkVerify	  2000	  42378761 ns/op (165uS/ver)

Winsupport NN=256 M=16KB
BenchmarkSign	    2000	  47992406 ns/op (187uS/sig)
BenchmarkVerify	   2000	  45140910 ns/op (176uS/ver)

Winsupport NN=256 M=1KB
BenchmarkSign	   10000	  11222923 ns/op (43uS/sig)
BenchmarkVerify	  3000	  27550708 ns/op (107uS/ver)

OpenSSL NN=256 M=1KB
BenchmarkSign	   10000	   8783652 ns/op (34us/sig)
BenchmarkVerify	  5000		24339433 ns/op (95us/ver)

Conclusion: openSSL is worth it on linux where its free. Not worth it
on windows
*/
func BenchmarkSign(b *testing.B) {

	//Things to sign
	const NN = 256
	targets := make([][]byte, NN)
	vks := make([][]byte, NN)
	sks := make([][]byte, NN)
	sigs := make([][]byte, NN)
	for i := 0; i < NN; i++ {
		//512 KB message
		targets[i] = make([]byte, 1*1024)
		rand.Read(targets[i])
		sks[i], vks[i] = GenerateKeypair()
		sigs[i] = make([]byte, 64)
	}
	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		for i := 0; i < NN; i++ {
			SignBlob(sks[i], vks[i], sigs[i], targets[i])
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	//Things to sign
	const NN = 256
	targets := make([][]byte, NN)
	vks := make([][]byte, NN)
	sks := make([][]byte, NN)
	sigs := make([][]byte, NN)
	for i := 0; i < NN; i++ {
		//512 KB message
		targets[i] = make([]byte, 1*1024)
		rand.Read(targets[i])
		sks[i], vks[i] = GenerateKeypair()
		sigs[i] = make([]byte, 64)
	}
	for i := 0; i < NN; i++ {
		SignBlob(sks[i], vks[i], sigs[i], targets[i])
	}
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		for i := 0; i < NN; i++ {
			ok := VerifyBlob(vks[i], sigs[i], targets[i])
			if !ok {
				panic("UH")
			}
		}
	}
}
