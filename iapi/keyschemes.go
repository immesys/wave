package iapi

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/crypto"
	"github.com/immesys/wave/serdes"
	"vuvuzela.io/crypto/ibe"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func EntityKeySchemeFor(e *serdes.EntityPublicKey) EntityKeyScheme {
	if e.Key.OID.Equal(serdes.EntityEd25519OID) {
		return &EntityKey_Ed25519{
			canonicalForm: e,
			PublicKey:     ed25519.PublicKey(e.Key.Content.(serdes.EntityPublicEd25519)),
		}
	}
	return &UnsupportedKeyScheme{canonicalForm: e}
}
func NewEntityKeyScheme(oid asn1.ObjectIdentifier) (EntitySecretKeyScheme, error) {
	switch {
	case oid.Equal(serdes.EntityEd25519OID):
		//Ed25519
		publicEd25519, privateEd25519, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapAttestation), int(CapCertification)},
				Key:          asn1.NewExternal(serdes.EntityPublicEd25519(publicEd25519)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretEd25519(privateEd25519)),
		}
		return &EntitySecretKey_Ed25519{canonicalForm: &ke,
			PublicKey:  publicEd25519,
			PrivateKey: privateEd25519}, nil
	case oid.Equal(serdes.EntityCurve25519OID):
		var secret [32]byte
		_, err := rand.Read(secret[:])
		if err != nil {
			return nil, err
		}
		var public [32]byte
		curve25519.ScalarBaseMult(&public, &secret)
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption)},
				Key:          asn1.NewExternal(serdes.EntityPublicCurve25519(public[:])),
			},
			Private: asn1.NewExternal(serdes.EntitySecretCurve25519(secret[:])),
		}
		_ = ke
		panic("ni")
	case oid.Equal(serdes.EntityIBE_BN256_ParamsOID):
		params, master := ibe.Setup(rand.Reader)
		paramsblob, err := params.MarshalBinary()
		if err != nil {
			return nil, err
		}
		masterblob, err := master.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption)},
				Key:          asn1.NewExternal(serdes.EntityParamsIBE_BN256(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterIBE_BN256(masterblob)),
		}
		_ = ke
		panic("ni")
	case oid.Equal(serdes.EntityOAQUE_BN256_S20_ParamsOID):
		params, master, err := crypto.GenerateOAQUEKeys()
		paramsblob := params.Marshal()
		if err != nil {
			return nil, err
		}
		masterblob := master.Marshal()
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption), int(CapAuthorization)},
				Key:          asn1.NewExternal(serdes.EntityParamsOQAUE_BN256_s20(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterOQAUE_BN256_s20(masterblob)),
		}
		_ = ke
		panic("ni")

	}
	panic("ni")
}

var _ EntityKeyScheme = &UnsupportedKeyScheme{}

type UnsupportedKeyScheme struct {
	canonicalForm *serdes.EntityPublicKey
}

func (k *UnsupportedKeyScheme) Is(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(k.canonicalForm.Key.OID)
}
func (k *UnsupportedKeyScheme) Supported() bool {
	return false
}
func (k *UnsupportedKeyScheme) IdentifyingBlob(ctx context.Context) (string, error) {
	return "", fmt.Errorf("key scheme %s is unsupported", k.canonicalForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) HasCapability(c Capability) bool {
	for _, has := range k.canonicalForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *UnsupportedKeyScheme) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.canonicalForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.canonicalForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.canonicalForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) EncryptMessageDH(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("key scheme %s is unsupported", k.canonicalForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) CanonicalForm(ctx context.Context) (*serdes.EntityPublicKey, error) {
	return k.canonicalForm, nil
}

var _ EntityKeyScheme = &EntityKey_Ed25519{}

type EntityKey_Ed25519 struct {
	canonicalForm *serdes.EntityPublicKey
	PublicKey     ed25519.PublicKey
}

func (ek *EntityKey_Ed25519) Is(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(serdes.EntityEd25519OID)
}
func (ek *EntityKey_Ed25519) IdentifyingBlob(ctx context.Context) (string, error) {
	return string(ek.PublicKey), nil
}
func (ek *EntityKey_Ed25519) Supported() bool {
	return true
}
func (ek *EntityKey_Ed25519) HasCapability(c Capability) bool {
	for _, has := range ek.canonicalForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntityKey_Ed25519) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	if !ek.HasCapability(CapCertification) {
		return fmt.Errorf("this key cannot perform certifications")
	}
	if ed25519.Verify(ek.PublicKey, data, signature) {
		return nil
	}
	return fmt.Errorf("ed25519 signature invalid")
}
func (ek *EntityKey_Ed25519) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	if !ek.HasCapability(CapAttestation) {
		return fmt.Errorf("this key cannot perform attestations")
	}
	if ed25519.Verify(ek.PublicKey, data, signature) {
		return nil
	}
	return fmt.Errorf("ed25519 signature invalid")
}

func (ek *EntityKey_Ed25519) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	if !ek.HasCapability(CapSigning) {
		return fmt.Errorf("this key cannot perform signing")
	}
	if ed25519.Verify(ek.PublicKey, data, signature) {
		return nil
	}
	return fmt.Errorf("ed25519 signature invalid")
}

func (ek *EntityKey_Ed25519) EncryptMessageDH(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (ek *EntityKey_Ed25519) CanonicalForm(ctx context.Context) (*serdes.EntityPublicKey, error) {
	return ek.canonicalForm, nil
}

var _ EntitySecretKeyScheme = &EntitySecretKey_Ed25519{}

type EntitySecretKey_Ed25519 struct {
	canonicalForm *serdes.EntityKeyringEntry
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
}

func (ek *EntitySecretKey_Ed25519) HasCapability(c Capability) bool {
	for _, has := range ek.canonicalForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntitySecretKey_Ed25519) CanonicalForm(ctx context.Context) (*serdes.EntityPublicKey, error) {
	return &ek.canonicalForm.Public, nil
}
func (ek *EntitySecretKey_Ed25519) SecretCanonicalForm(ctx context.Context) (*serdes.EntityKeyringEntry, error) {
	return ek.canonicalForm, nil
}
func (ek *EntitySecretKey_Ed25519) DecryptMessageDH(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (ek *EntitySecretKey_Ed25519) GenerateChildKey(ctx context.Context, identity interface{}) (EntitySecretKeyScheme, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (ek *EntitySecretKey_Ed25519) Public() (EntityKeyScheme, error) {
	return &EntityKey_Ed25519{
		canonicalForm: &ek.canonicalForm.Public,
		PublicKey:     ek.PublicKey,
	}, nil
}

//Signing signature bindings or signing DER (for ephemeral)

func (ek *EntitySecretKey_Ed25519) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	if !ek.HasCapability(CapSigning) {
		return nil, fmt.Errorf("this key cannot perform signing")
	}
	sig := ed25519.Sign(ek.PrivateKey, content)
	return sig, nil
}
func (ek *EntitySecretKey_Ed25519) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	if !ek.HasCapability(CapCertification) {
		return nil, fmt.Errorf("this key cannot perform certification")
	}
	sig := ed25519.Sign(ek.PrivateKey, content)
	return sig, nil
}
func (ek *EntitySecretKey_Ed25519) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	if !ek.HasCapability(CapAttestation) {
		return nil, fmt.Errorf("this key cannot perform attestation")
	}
	sig := ed25519.Sign(ek.PrivateKey, content)
	return sig, nil
}
