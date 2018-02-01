package serdes

import "github.com/immesys/asn1"

type WR1BodyCiphertext struct {
	VerifierBodyCiphertext []byte
	ProverBodyCiphertext   []byte
	EnvelopeCiphertext     []byte
	EnvelopeKey_IBE_BN256  []byte
	EnvelopeKey_Curve25519 []byte
}

type WR1Envelope struct {
	VerifierBodyKey_OAQUE []byte
	Partition             [][]byte
}

type WR1ProverBody struct {
	Addendums []asn1.External
}

type WR1VerifierBody struct {
	AttestationVerifierBody AttestationVerifierBody
}

type Ed25519OuterSignature struct {
	VerifyingKey []byte
	Signature    []byte
}

type SignedOuterKey struct {
	TBS struct {
		OuterSignatureScheme asn1.ObjectIdentifier
		VerifyingKey         []byte
	}
	Signature []byte
}

type PublicEd25519 []byte
type PublicCurve25519 []byte
type PublicOAQUE_BN256_s20 [][]byte
type ParamsOQAUE_BN256_s20 []byte
type ParamsIBE_BN256 []byte
type PublicIBE []byte
