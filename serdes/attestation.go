package serdes

import (
	"time"

	"github.com/immesys/asn1"
)

type WaveAttestation struct {
	TBS struct {
		Subject          asn1.External //EntityHash
		SubjectLocation  asn1.External //Location
		Revocations      []RevocationOption
		PublicExtensions []Extension
		Body             asn1.External
	}
	OuterSignature asn1.External
}

type AttestationBody struct {
	VerifierBody          AttestationVerifierBody
	ProverPolicyAddendums []asn1.External
	ProverExtensions      []Extension
}

type AttestationVerifierBody struct {
	Attester         asn1.External //EntityHash
	AttesterLocation asn1.External //Location
	//Subject  asn1.External //EntityHash
	Validity struct {
		NotBefore time.Time `asn1:"utc"`
		NotAfter  time.Time `asn1:"utc"`
	}
	Policy                asn1.External
	Extensions            []Extension
	OuterSignatureBinding asn1.External
}

type TrustLevel struct {
	Trust int
}

type RTreePolicy struct {
	Namespace    asn1.External //EntityHash
	Indirections int
	Statements   []RTreeStatement
}

type RTreeStatement struct {
	PermissionSet asn1.External
	Permissions   []string
	Resource      string
}

type SignedOuterKey struct {
	TBS struct {
		OuterSignatureScheme asn1.ObjectIdentifier
		VerifyingKey         []byte
	}
	Signature []byte
}

type PSKBodyCiphertext struct {
	AttestationBodyCiphetext []byte
	EncryptedUnder           EntityPublicKey
}

type WaveExplicitProof struct {
	Attestations []AttestationReference
	Paths        [][]int
	Extensions   []Extension
}

type AttestationReference struct {
	Hash             asn1.External
	Content          []byte          `asn1:"tag:0,optional"`
	Locations        []asn1.External `asn1:"tag:1"`
	Keys             []asn1.External `asn1:"tag:2"`
	RevocationChecks []asn1.External `asn1:"tag:3"`
	Extensions       []Extension     `asn1:"tag:4"`
}
