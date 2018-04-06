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

type EntityPublicIBE_BN256 struct {
	Params EntityParamsIBE_BN256
	ID     []byte
}
type EntityPublicOAQUE_BN256_s20 struct {
	Params       EntityParamsOQAUE_BN256_s20
	AttributeSet [][]byte
}
type EntityPublicEd25519 []byte
type EntityPublicCurve25519 []byte
type EntityParamsOQAUE_BN256_s20 []byte
type EntityParamsIBE_BN256 []byte

type EntitySecretEd25519 []byte
type EntitySecretCurve25519 []byte
type EntitySecretOQAUE_BN256_s20 []byte
type EntitySecretMasterOQAUE_BN256_s20 []byte
type EntitySecretMasterIBE_BN256 []byte
type EntitySecretIBE_BN256 []byte

type KeyringAESCiphertext struct {
	Ciphertext []byte
	Salt       []byte
	Iterations int
}

type WR1DomainVisibilityKey_IBE_BN256 EntityKeyringEntry
type WR1PartitionKey_OAQUE_BN256_s20 EntityKeyringEntry
type WR1EncryptionKey_OAQUE_BN256_s20 EntityKeyringEntry

type AVKeyAES128GCM []byte
