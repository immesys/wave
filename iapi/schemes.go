package iapi

import (
	"context"
	"encoding/asn1"

	"github.com/immesys/wave/serdes"
)

// In all of these, the context is assumed to contain the perspective entity secret

type Scheme interface {
	Is(asn1.ObjectIdentifier) bool
	Supported() bool
}

type RevocationScheme interface {
	Scheme
}

type DecryptionContext interface {
	//Specific to body scheme
}

type AttestationBodyScheme interface {
	Scheme
	DecryptBodyAsProver(ctx context.Context, dc DecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error)
	DecryptBodyAsVerifier(ctx context.Context, vks AttestationVerifierKeyScheme, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error)
}

type OuterSignatureScheme interface {
	Scheme
	VerifySignature(ctx context.Context, canonicalForm *serdes.WaveAttestation) error
}

type PolicyAddendumScheme interface {
	Scheme
}

type HashScheme interface {
	Scheme
	Digest(ctx context.Context, input []byte) ([]byte, error)
}

//PolicyScheme gets its own file

type OuterSignatureBindingScheme interface {
	Scheme
	VerifyBinding(ctx context.Context, decodedForm *serdes.WaveAttestation) error
}

type LocationScheme interface {
	Scheme
}

type EntityKeyringScheme interface {
	Scheme
	DecryptKeyring(ctx context.Context, canonicalForm *serdes.WaveEntitySecret, params interface{}) (decodedForm *serdes.EntityKeyring, err error)
}

type EntitySecretKeyScheme interface {
	EntityKeyScheme
	SignCertify(ctx context.Context, publickey []byte) ([]byte, error)
	//Signing signature bindings or signing DER (for ephemeral)
	SignAttestation(ctx context.Context, content []byte) ([]byte, error)
	SignMessage(ctx context.Context, content []byte) ([]byte, error)
	EncryptMessage(ctx context.Context, to EntityKeyScheme, content []byte) ([]byte, error)
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

type EntityKeyScheme interface {
	Scheme
	//Such as the public key, used for comparing keys to check private matches
	IdentifyingBlob(ctx context.Context) (string, error)
	HasCapability(c Capability) bool
	VerifyCertify(ctx context.Context, signature []byte) error
	VerifyAttestation(ctx context.Context, signature []byte) error
	VerifyMessage(ctx context.Context, signature []byte) error
	DecryptMessage(ctx context.Context, signature []byte) ([]byte, error)
}

type AttestationVerifierKeyScheme interface {
	Scheme
	DecryptBody(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type ExtensionScheme interface {
	Scheme
	IsCritical() bool
}
