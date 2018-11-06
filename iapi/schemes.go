package iapi

import (
	"context"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

// In all of these, the context is assumed to contain the perspective entity secret

type Scheme interface {
	Supported() bool
}

type VerificationContext interface {
	EntityByHashLoc(ctx context.Context, h HashSchemeInstance, loc LocationSchemeInstance) (*Entity, wve.WVE)
	AttestationByHashLoc(ctx context.Context, h HashSchemeInstance, loc LocationSchemeInstance) (*Attestation, wve.WVE)
}

type BodyDecryptionContext interface {
	EntityByHashLoc(ctx context.Context, h HashSchemeInstance, loc LocationSchemeInstance) (*Entity, wve.WVE)
}
type BodyEncryptionContext interface {
	//EntityFromHash(ctx context.Context, hash HashScheme) (Entity, error)
}
type AttestationBodyScheme interface {
	Scheme
	DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation, inextra interface{}) (decodedForm *serdes.AttestationBody, extra interface{}, err error)
	EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error)
}

type OuterSignatureScheme interface {
	Scheme
	VerifySignature(ctx context.Context, canonicalForm *serdes.WaveAttestation) wve.WVE
}

type PolicySchemeInstance interface {
	Scheme
	CanonicalForm() *asn1.External
	//These are required for WR1 support
	WR1DomainEntity() HashSchemeInstance
	//The first 12 elements used in the final partition
	WR1PartitionPrefix() [][]byte
	CheckValid() error
}
type PolicyAddendumSchemeInstance interface {
	Scheme
}
type RevocationSchemeInstance interface {
	Scheme
	CanonicalForm() serdes.RevocationOption
	IsRevoked(ctx context.Context, s StorageInterface) (bool, wve.WVE)
	Critical() bool
	Id() string
}
type HashScheme interface {
	Scheme
	//Digest(ctx context.Context, input []byte) ([]byte, error)
	Instance(input []byte) HashSchemeInstance
	OID() asn1.ObjectIdentifier
}
type HashSchemeInstance interface {
	Scheme
	//For curried hash scheme instances
	Value() []byte
	Multihash() []byte
	MultihashString() string
	CanonicalForm() *asn1.External
	OID() asn1.ObjectIdentifier
}

//PolicyScheme gets its own file

type OuterSignatureBindingScheme interface {
	Scheme
	VerifyBinding(ctx context.Context, att *Attestation, attester *Entity) wve.WVE
}

type LocationSchemeInstance interface {
	Scheme
	CanonicalForm() *asn1.External
	IdHash() [32]byte
	Equal(l LocationSchemeInstance) bool
}

type EntityKeyringSchemeInstance interface {
	Scheme
	DecryptKeyring(ctx context.Context, params interface{}) (decodedForm *serdes.EntityKeyring, err error)
	EncryptKeyring(ctx context.Context, plaintext *serdes.EntityKeyring, params interface{}) (encodedForm *asn1.External, err error)
	//CanonicalForm(ctx context.Context) (*asn1.External, error)
}

type EntitySecretKeySchemeInstance interface {
	Scheme
	Public() EntityKeySchemeInstance
	SignCertify(ctx context.Context, content []byte) ([]byte, error)
	//Signing signature bindings or signing DER (for ephemeral)
	SignAttestation(ctx context.Context, content []byte) ([]byte, error)
	SignMessage(ctx context.Context, content []byte) ([]byte, error)
	DecryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error)
	DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error)
	GenerateChildSecretKey(ctx context.Context, identity interface{}, delegable bool) (EntitySecretKeySchemeInstance, error)
	SecretCanonicalForm() *serdes.EntityKeyringEntry
	Equal(rhs EntitySecretKeySchemeInstance) bool
}
type SlottedSecretKey interface {
	EntitySecretKeySchemeInstance
	Slots() [][]byte
	IdHash() [32]byte
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
	SystemIdentifyingBlob(ctx context.Context) (string, error)
	HasCapability(c Capability) bool
	VerifyCertify(ctx context.Context, data []byte, signature []byte) error
	VerifyAttestation(ctx context.Context, data []byte, signature []byte) error
	VerifyMessage(ctx context.Context, data []byte, signature []byte) error
	EncryptMessage(ctx context.Context, content []byte) ([]byte, error)
	GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error)
	CanonicalForm() *serdes.EntityPublicKey
}

type AttestationVerifierBodyKeySchemeInstance interface {
	Scheme
	DecryptBody(ctx context.Context, ciphertext []byte) ([]byte, error)
}
type ExtensionSchemeInstance interface {
	Scheme
	IsCritical() bool
}
