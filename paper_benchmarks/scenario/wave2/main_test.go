package main

import (
	"testing"
)

var proof []byte
var proof3 []byte

func init() {
	Init()
	proof = MakePolicy()
	proof3 = MakePolicy3()
	//fmt.Printf("proof3: %x\n", proof3)
}

func BenchmarkGetPolicy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetPolicy(proof)
	}
}

func BenchmarkGetPolicy3(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetPolicy(proof3)
	}
}
