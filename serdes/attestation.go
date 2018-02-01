package serdes

import (
	"time"

	"github.com/immesys/asn1"
)

/*
type WaveAttestation struct {
	TBS struct {
		Subject          asn1.External //EntityHash
		Revocations      []RevocationOption
		PublicExtensions []Extension
		Body             asn1.External
	}
	OuterSignature asn1.External
}
*/
type WaveAttestation struct {
	K   int
	TBS struct {
		I int
	}
	j int
}

type AttestationBody struct {
	VerifierBody          AttestationVerifierBody
	ProverPolicyAddendums []asn1.External
	ProverExtensions      []Extension
}

type AttestationVerifierBody struct {
	Attester asn1.External //EntityHash
	Subject  asn1.External //EntityHash
	Validity struct {
		NotBefore time.Time `asn1:"utc"`
		NotAfter  time.Time `asn1:"utc"`
	}
	Policy                asn1.External
	Extensions            []Extension
	OuterSignatureBidning asn1.External
}
