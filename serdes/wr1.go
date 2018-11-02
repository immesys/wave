package serdes

import "github.com/immesys/asn1"

type WR1BodyCiphertext struct {
	VerifierBodyCiphertext         []byte
	ProverBodyCiphertext           []byte
	EnvelopeCiphertext             []byte
	EnvelopeKey_IBE_BLS12381       []byte
	EnvelopeKey_Curve25519         []byte
	EnvelopeKey_Curve25519Attester []byte
}

type WR1Envelope struct {
	BodyKeys_OAQUE []byte
	Partition      [][]byte
}

type WR1ProverBody struct {
	Addendums  []asn1.External
	Extensions []Extension
}

type WR1VerifierBody struct {
	AttestationVerifierBody AttestationVerifierBody
}

type Ed25519OuterSignature struct {
	VerifyingKey []byte
	Signature    []byte
}

type EntityPublicIBE_BLS12381 struct {
	Params EntityParamsIBE_BLS12381
	ID     []byte
}
type EntityPublicOAQUE_BLS12381_s20 struct {
	Params       EntityParamsOQAUE_BLS12381_s20
	AttributeSet [][]byte
}
type EntityPublicEd25519 []byte
type EntityPublicCurve25519 []byte
type EntityParamsOQAUE_BLS12381_s20 []byte
type EntityParamsIBE_BLS12381 []byte

type EntitySecretEd25519 []byte
type EntitySecretCurve25519 []byte
type EntitySecretOQAUE_BLS12381_s20 []byte
type EntitySecretMasterOQAUE_BLS12381_s20 []byte
type EntitySecretMasterIBE_BLS12381 []byte
type EntitySecretIBE_BLS12381 []byte

type KeyringAESCiphertext struct {
	Ciphertext []byte
	Salt       []byte
	Iterations int
}

type WR1DomainVisibilityKey_IBE_BLS12381 EntityKeyringEntry
type WR1PartitionKey_OAQUE_BLS12381_s20 EntityKeyringEntry

type AVKeyAES128GCM []byte
