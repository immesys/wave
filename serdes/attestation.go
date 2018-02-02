package serdes

import (
	"time"

	"github.com/immesys/asn1"
)

type WaveAttestation struct {
	TBS struct {
		Subject          asn1.External //EntityHash
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
	Attester asn1.External //EntityHash
	Subject  asn1.External //EntityHash
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
