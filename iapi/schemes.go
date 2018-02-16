package iapi

import (
	"context"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

// In all of these, the context is assumed to contain the perspective entity secret

type Scheme interface {
	Supported() bool
}

type RevocationScheme interface {
	Scheme
}

type BodyDecryptionContext interface {
}
type BodyEncryptionContext interface {
	//EntityFromHash(ctx context.Context, hash HashScheme) (Entity, error)
}
type AttestationBodyScheme interface {
	Scheme
	DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error)
	EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error)
}

type OuterSignatureSchemeInstance interface {
	Scheme
	VerifySignature(ctx context.Context, canonicalForm *serdes.WaveAttestation) error
}

type PolicySchemeInstance interface {
	Scheme
	CanonicalForm(ctx context.Context) (*asn1.External, error)
	//These are required for WR1 support
	WR1DomainEntity(ctx context.Context) (HashScheme, error)
	WR1Partition(ctx context.Context) ([][]byte, error)
}
type PolicyAddendumSchemeInstance interface {
	Scheme
}

type HashScheme interface {
	Scheme
	//Digest(ctx context.Context, input []byte) ([]byte, error)
	Instance(input []byte) (HashSchemeInstance, error)
}
type HashSchemeInstance interface {
	Scheme
	//For curried hash scheme instances
	Value() []byte
	CanonicalForm() (*asn1.External, error)
}

//PolicyScheme gets its own file

type OuterSignatureBindingScheme interface {
	Scheme
	VerifyBinding(ctx context.Context, decodedForm *serdes.WaveAttestation) error
}

type LocationSchemeInstance interface {
	Scheme
	Equal(l LocationSchemeInstance) bool
}

type EntityKeyringSchemeInstance interface {
	Scheme
	DecryptKeyring(ctx context.Context, params interface{}) (decodedForm *serdes.EntityKeyring, err error)
	EncryptKeyring(ctx context.Context, plaintext *serdes.EntityKeyring, params interface{}) (encodedForm *asn1.External, err error)
	//CanonicalForm(ctx context.Context) (*asn1.External, error)
}

type EntitySecretKeySchemeInstance interface {
	Public() (EntityKeySchemeInstance, error)
	SignCertify(ctx context.Context, content []byte) ([]byte, error)
	//Signing signature bindings or signing DER (for ephemeral)
	SignAttestation(ctx context.Context, content []byte) ([]byte, error)
	SignMessage(ctx context.Context, content []byte) ([]byte, error)
	DecryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error)
	DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error)
	GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error)
	SecretCanonicalForm(ctx context.Context) (*serdes.EntityKeyringEntry, error)
	Equal(rhs EntitySecretKeySchemeInstance) bool
}
type SlottedSecretKey interface {
	EntitySecretKeySchemeInstance
	Slots() [][]byte
}

type Capability int

const (
	CapCertification  Capability = 1
	CapAttestation    Capability = 2
	CapSigning        Capability = 3
	CapAuthentication Capability = 4
	CapAuthorization  Capability = 5
	CapEncryption     Capability = 6
)

type EntityKeySchemeInstance interface {
	Scheme
	//Such as the public key, used for comparing keys to check private matches
	IdentifyingBlob(ctx context.Context) (string, error)
	HasCapability(c Capability) bool
	VerifyCertify(ctx context.Context, data []byte, signature []byte) error
	VerifyAttestation(ctx context.Context, data []byte, signature []byte) error
	VerifyMessage(ctx context.Context, data []byte, signature []byte) error
	EncryptMessage(ctx context.Context, content []byte) ([]byte, error)
	GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error)
	CanonicalForm(ctx context.Context) (*serdes.EntityPublicKey, error)
}

type AttestationVerifierKeySchemeInstance interface {
	Scheme
	DecryptBody(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type ExtensionSchemeInstance interface {
	Scheme
	IsCritical() bool
}
