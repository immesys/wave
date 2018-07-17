package main

import (
	"os"
	"testing"
)

func init() {
	Init()
}

func BenchmarkGetPolicy(b *testing.B) {
	proof := []byte("m.andersen:" + os.Getenv("LDAP_PASS"))
	for i := 0; i < b.N; i++ {
		GetPolicy(proof)
	}
}
