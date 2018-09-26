package iapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/ucbrise/starwave/crypto/cryptutils"
	"github.com/ucbrise/starwave/crypto/oaque"
	"github.com/ucbrise/vuvuzelacrypto/ibe"
	bn256 "vuvuzela.io/crypto/bn256"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

func EntityKeySchemeInstanceFor(e *serdes.EntityPublicKey) (EntityKeySchemeInstance, error) {
	switch {
	case e.Key.OID.Equal(serdes.EntityEd25519OID):
		if len(e.Key.Content.(serdes.EntityPublicEd25519)) != 32 {
			return nil, fmt.Errorf("key length is incorrect")
		}
		return &EntityKey_Ed25519{
			SerdesForm: e,
			PublicKey:  ed25519.PublicKey(e.Key.Content.(serdes.EntityPublicEd25519)),
		}, nil
	case e.Key.OID.Equal(serdes.EntityCurve25519OID):
		ba := [32]byte{}
		if len(e.Key.Content.(serdes.EntityPublicCurve25519)) != 32 {
			return nil, fmt.Errorf("key length is incorrect")
		}
		copy(ba[:], e.Key.Content.(serdes.EntityPublicCurve25519))
		return &EntityKey_Curve25519{
			SerdesForm: e,
			PublicKey:  ba,
		}, nil
	case e.Key.OID.Equal(serdes.EntityIBE_BN256_ParamsOID):
		rv := &EntityKey_IBE_Params_BN256{
			SerdesForm: e,
			PublicKey:  &ibe.MasterPublicKey{},
		}
		err := rv.PublicKey.UnmarshalBinary(e.Key.Content.(serdes.EntityParamsIBE_BN256))
		if err != nil {
			return nil, err
		}
		return rv, nil
	case e.Key.OID.Equal(serdes.EntityIBE_BN256_PublicOID):
		rv := &EntityKey_IBE_BN256{
			SerdesForm: e,
			Params:     &ibe.MasterPublicKey{},
		}
		obj := e.Key.Content.(serdes.EntityPublicIBE_BN256)
		rv.ID = obj.ID
		err := rv.Params.UnmarshalBinary(obj.Params)
		if err != nil {
			return nil, err
		}
		return rv, nil
	case e.Key.OID.Equal(serdes.EntityOAQUE_BN256_S20_ParamsOID):
		rv := &EntityKey_OAQUE_BN256_S20_Params{
			SerdesForm: e,
			Params:     &oaque.Params{},
		}
		blob := e.Key.Content.(serdes.EntityParamsOQAUE_BN256_s20)
		ok := rv.Params.Unmarshal(blob)
		if !ok {
			return nil, fmt.Errorf("could not unmarshal oaque params")
		}
		return rv, nil
	case e.Key.OID.Equal(serdes.EntityOAQUE_BN256_S20_AttributeSetOID):
		rv := &EntityKey_OAQUE_BN256_S20{
			SerdesForm: e,
			Params:     &oaque.Params{},
		}
		obj := e.Key.Content.(serdes.EntityPublicOAQUE_BN256_s20)
		rv.AttributeSet = obj.AttributeSet
		ok := rv.Params.Unmarshal(obj.Params)
		if !ok {
			return nil, fmt.Errorf("could not unmarshal oaque params")
		}
		return rv, nil
	}
	return &UnsupportedKeyScheme{SerdesForm: e}, nil
}
func EntitySecretKeySchemeInstanceFor(e *serdes.EntityKeyringEntry) (EntitySecretKeySchemeInstance, error) {
	switch {
	case e.Private.OID.Equal(serdes.EntitySecretEd25519OID):
		return &EntitySecretKey_Ed25519{
			SerdesForm: e,
			PublicKey:  ed25519.PublicKey(e.Public.Key.Content.(serdes.EntityPublicEd25519)),
			PrivateKey: ed25519.PrivateKey(e.Private.Content.(serdes.EntitySecretEd25519)),
		}, nil
	case e.Private.OID.Equal(serdes.EntitySecretCurve25519OID):
		pub := [32]byte{}
		prv := [32]byte{}
		copy(pub[:], e.Public.Key.Content.(serdes.EntityPublicCurve25519))
		copy(prv[:], e.Private.Content.(serdes.EntitySecretCurve25519))
		return &EntitySecretKey_Curve25519{
			SerdesForm: e,
			PublicKey:  pub,
			PrivateKey: prv,
		}, nil
	case e.Private.OID.Equal(serdes.EntitySecretIBE_BN256_MasterOID):
		mk := ibe.MasterPrivateKey{}
		err := mk.UnmarshalBinary(e.Private.Content.(serdes.EntitySecretMasterIBE_BN256))
		if err != nil {
			return nil, err
		}
		params := ibe.MasterPublicKey{}
		err = params.UnmarshalBinary(e.Public.Key.Content.(serdes.EntityParamsIBE_BN256))
		if err != nil {
			return nil, err
		}
		return &EntitySecretKey_IBE_Master_BN256{
			SerdesForm: e,
			PublicKey:  &params,
			PrivateKey: &mk,
		}, nil
	case e.Private.OID.Equal(serdes.EntitySecretIBE_BN256OID):
		obj := e.Public.Key.Content.(serdes.EntityPublicIBE_BN256)
		params := ibe.MasterPublicKey{}
		err := params.UnmarshalBinary(obj.Params)
		if err != nil {
			return nil, err
		}
		priv := ibe.IdentityPrivateKey{}
		err = priv.UnmarshalBinary(e.Private.Content.(serdes.EntitySecretIBE_BN256))
		if err != nil {
			return nil, err
		}
		return &EntitySecretKey_IBE_BN256{
			SerdesForm: e,
			Params:     &params,
			PrivateKey: &priv,
			ID:         obj.ID,
		}, nil
	case e.Private.OID.Equal(serdes.EntitySecretOAQUE_BN256_S20OID):
		obj := e.Public.Key.Content.(serdes.EntityPublicOAQUE_BN256_s20)
		params := oaque.Params{}
		ok := params.Unmarshal(obj.Params)
		if !ok {
			return nil, fmt.Errorf("cannot unmarshal oaque params")
		}
		priv := oaque.PrivateKey{}
		ok = priv.Unmarshal(e.Private.Content.(serdes.EntitySecretOQAUE_BN256_s20))
		if !ok {
			return nil, fmt.Errorf("cannot unmarshal oaque params")
		}
		return &EntitySecretKey_OAQUE_BN256_S20{
			SerdesForm:   e,
			Params:       &params,
			PrivateKey:   &priv,
			AttributeSet: obj.AttributeSet,
		}, nil
	case e.Private.OID.Equal(serdes.EntitySecretOAQUE_BN256_S20_MasterOID):
		mk := oaque.MasterKey{}
		ok := mk.Unmarshal(e.Private.Content.(serdes.EntitySecretMasterOQAUE_BN256_s20))
		if !ok {
			return nil, fmt.Errorf("cannot unmarshal oaque master")
		}
		parba := e.Public.Key.Content.(serdes.EntityParamsOQAUE_BN256_s20)
		params := oaque.Params{}
		ok = params.Unmarshal(parba)
		if !ok {
			return nil, fmt.Errorf("cannot unmarshal oaque master")
		}
		return &EntitySecretKey_OAQUE_BN256_S20_Master{
			SerdesForm: e,
			Params:     &params,
			PrivateKey: &mk,
		}, nil
	}
	return &UnsupportedSecretKeyScheme{SerdesForm: e}, nil
}
func NewEntityKeySchemeInstance(oid asn1.ObjectIdentifier, capabilities ...Capability) (EntitySecretKeySchemeInstance, error) {
	checkcap := func(expected ...Capability) ([]int, error) {
	outer:
		for _, in := range capabilities {
			for _, ex := range expected {
				if in == ex {
					break outer
				}
			}
			return nil, fmt.Errorf("this key cannot provide the requested capability")
		}
		capz := []int{}
		for _, c := range capabilities {
			capz = append(capz, int(c))
		}
		return capz, nil
	}
	switch {
	case oid.Equal(serdes.EntityEd25519OID):
		//Ed25519
		capz, err := checkcap(CapSigning, CapAttestation, CapCertification, CapAuthentication)
		if err != nil {
			return nil, err
		}
		publicEd25519, privateEd25519, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: capz,
				Key:          asn1.NewExternal(serdes.EntityPublicEd25519(publicEd25519)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretEd25519(privateEd25519)),
		}
		return &EntitySecretKey_Ed25519{SerdesForm: &ke,
			PublicKey:  publicEd25519,
			PrivateKey: privateEd25519}, nil
	case oid.Equal(serdes.EntityCurve25519OID):
		capz, err := checkcap(CapEncryption)
		if err != nil {
			return nil, err
		}
		var secret [32]byte
		_, err = rand.Read(secret[:])
		if err != nil {
			return nil, err
		}
		var public [32]byte
		curve25519.ScalarBaseMult(&public, &secret)
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: capz,
				Key:          asn1.NewExternal(serdes.EntityPublicCurve25519(public[:])),
			},
			Private: asn1.NewExternal(serdes.EntitySecretCurve25519(secret[:])),
		}
		return &EntitySecretKey_Curve25519{SerdesForm: &ke,
			PublicKey:  public,
			PrivateKey: secret}, nil
	case oid.Equal(serdes.EntityIBE_BN256_ParamsOID):
		capz, err := checkcap(CapEncryption)
		if err != nil {
			return nil, err
		}
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
				Capabilities: capz,
				Key:          asn1.NewExternal(serdes.EntityParamsIBE_BN256(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterIBE_BN256(masterblob)),
		}
		return &EntitySecretKey_IBE_Master_BN256{
			SerdesForm: &ke,
			PrivateKey: master,
			PublicKey:  params,
		}, nil

	case oid.Equal(serdes.EntityOAQUE_BN256_S20_ParamsOID):
		capz, err := checkcap(CapEncryption)
		if err != nil {
			return nil, err
		}
		params, master, err := oaque.Setup(rand.Reader, 20, true)
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
				Capabilities: capz,
				Key:          asn1.NewExternal(serdes.EntityParamsOQAUE_BN256_s20(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterOQAUE_BN256_s20(masterblob)),
		}
		return &EntitySecretKey_OAQUE_BN256_S20_Master{
			SerdesForm: &ke,
			Params:     params,
			PrivateKey: master,
		}, nil
	}
	return nil, fmt.Errorf("unknown key scheme")
}

var _ EntityKeySchemeInstance = &UnsupportedKeyScheme{}

type UnsupportedKeyScheme struct {
	SerdesForm *serdes.EntityPublicKey
}

func (k *UnsupportedKeyScheme) Supported() bool {
	return false
}
func (k *UnsupportedKeyScheme) IdentifyingBlob(ctx context.Context) (string, error) {
	return "", fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	return "", fmt.Errorf("Unsupported key scheme")
}
func (k *UnsupportedKeyScheme) HasCapability(c Capability) bool {
	for _, has := range k.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *UnsupportedKeyScheme) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	return nil, fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) EncryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("key scheme %s is unsupported", k.SerdesForm.Key.OID.String())
}
func (k *UnsupportedKeyScheme) CanonicalForm() *serdes.EntityPublicKey {
	panic("CanonicalForm called on unsupported key scheme")
}

var _ EntityKeySchemeInstance = &EntityKey_Ed25519{}

type EntityKey_Ed25519 struct {
	SerdesForm *serdes.EntityPublicKey
	PublicKey  ed25519.PublicKey
}

func (ek *EntityKey_Ed25519) Supported() bool {
	return true
}
func (ek *EntityKey_Ed25519) IdentifyingBlob(ctx context.Context) (string, error) {
	return string(ek.PublicKey), nil
}
func (ek *EntityKey_Ed25519) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	return "", fmt.Errorf("this key is not part of a system")
}
func (ek *EntityKey_Ed25519) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Capabilities {
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
func (ek *EntityKey_Ed25519) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (ek *EntityKey_Ed25519) EncryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (ek *EntityKey_Ed25519) CanonicalForm() *serdes.EntityPublicKey {
	return ek.SerdesForm
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_Ed25519{}

type EntitySecretKey_Ed25519 struct {
	SerdesForm *serdes.EntityKeyringEntry
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func (ek *EntitySecretKey_Ed25519) Supported() bool {
	return true
}
func (ek *EntitySecretKey_Ed25519) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntitySecretKey_Ed25519) CanonicalForm() *serdes.EntityPublicKey {
	return &ek.SerdesForm.Public
}
func (ek *EntitySecretKey_Ed25519) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return ek.SerdesForm
}
func (ek *EntitySecretKey_Ed25519) DecryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (ek *EntitySecretKey_Ed25519) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	return nil, fmt.Errorf("this key does not support such decryption")
}
func (ek *EntitySecretKey_Ed25519) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (ek *EntitySecretKey_Ed25519) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_Ed25519)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Private.Bytes, ekrhs.SerdesForm.Private.Bytes)
}
func (ek *EntitySecretKey_Ed25519) Public() EntityKeySchemeInstance {
	return &EntityKey_Ed25519{
		SerdesForm: &ek.SerdesForm.Public,
		PublicKey:  ek.PublicKey,
	}
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

var _ EntityKeySchemeInstance = &EntityKey_Curve25519{}

type EntityKey_Curve25519 struct {
	SerdesForm *serdes.EntityPublicKey
	PublicKey  [32]byte
}

func (ek *EntityKey_Curve25519) Supported() bool {
	return true
}
func (ek *EntityKey_Curve25519) IdentifyingBlob(ctx context.Context) (string, error) {
	return string(ek.PublicKey[:]), nil
}
func (ek *EntityKey_Curve25519) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	return "", fmt.Errorf("this key is not part of a system")
}
func (ek *EntityKey_Curve25519) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntityKey_Curve25519) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform certifications")
}
func (ek *EntityKey_Curve25519) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform attestations")
}

func (ek *EntityKey_Curve25519) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform signing")
}
func (ek *EntityKey_Curve25519) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (ek *EntityKey_Curve25519) EncryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	ephemeral_secret_key := [32]byte{}
	rand.Read(ephemeral_secret_key[:])
	ephemeral_secret_key[0] &= 248
	ephemeral_secret_key[31] &= 127
	ephemeral_secret_key[31] |= 64
	publickey := [32]byte{}
	curve25519.ScalarBaseMult(&publickey, &ephemeral_secret_key)
	sharedsecretsource := [32]byte{}
	curve25519.ScalarMult(&sharedsecretsource, &ephemeral_secret_key, &ek.PublicKey)

	sharedsecret := sha3.Sum256(sharedsecretsource[:])
	key := sharedsecret[:16]
	nonce := sharedsecret[16:28]
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	rv := make([]byte, 32+len(ciphertext))
	copy(rv[:32], publickey[:])
	copy(rv[32:], ciphertext)
	return rv, nil
}
func (ek *EntityKey_Curve25519) CanonicalForm() *serdes.EntityPublicKey {
	return ek.SerdesForm
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_Curve25519{}

type EntitySecretKey_Curve25519 struct {
	SerdesForm *serdes.EntityKeyringEntry
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func (ek *EntitySecretKey_Curve25519) Supported() bool {
	return true
}
func (ek *EntitySecretKey_Curve25519) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntitySecretKey_Curve25519) CanonicalForm() *serdes.EntityPublicKey {
	return &ek.SerdesForm.Public
}
func (ek *EntitySecretKey_Curve25519) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return ek.SerdesForm
}
func (ek *EntitySecretKey_Curve25519) DecryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	ephemeral_public_key := [32]byte{}
	copy(ephemeral_public_key[:], data[0:32])
	sharedsecretsource := [32]byte{}
	curve25519.ScalarMult(&sharedsecretsource, &ek.PrivateKey, &ephemeral_public_key)

	sharedsecret := sha3.Sum256(sharedsecretsource[:])
	key := sharedsecret[:16]
	nonce := sharedsecret[16:28]
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, data[32:], nil)
	if err != nil {
		return nil, fmt.Errorf("gcm check failed")
	}
	return plaintext, nil
}
func (ek *EntitySecretKey_Curve25519) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	return nil, fmt.Errorf("this key does not support such decryption")
}
func (ek *EntitySecretKey_Curve25519) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_Curve25519)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Private.Bytes, ekrhs.SerdesForm.Private.Bytes)
}
func (ek *EntitySecretKey_Curve25519) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (ek *EntitySecretKey_Curve25519) Public() EntityKeySchemeInstance {
	return &EntityKey_Curve25519{
		SerdesForm: &ek.SerdesForm.Public,
		PublicKey:  ek.PublicKey,
	}
}
func (ek *EntitySecretKey_Curve25519) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform signing")
}
func (ek *EntitySecretKey_Curve25519) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform certification")
}
func (ek *EntitySecretKey_Curve25519) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform attestation")
}

var _ EntitySecretKeySchemeInstance = &UnsupportedSecretKeyScheme{}

type UnsupportedSecretKeyScheme struct {
	SerdesForm *serdes.EntityKeyringEntry
}

func (ek *UnsupportedSecretKeyScheme) Supported() bool {
	return false
}
func (ek *UnsupportedSecretKeyScheme) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *UnsupportedSecretKeyScheme) CanonicalForm() *serdes.EntityPublicKey {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) DecryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) Public() EntityKeySchemeInstance {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) Equal(rhs EntitySecretKeySchemeInstance) bool {
	return false
}
func (k *UnsupportedSecretKeyScheme) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	panic("Operation called on unsupported secret key scheme")
}
func (k *UnsupportedSecretKeyScheme) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	panic("Operation called on unsupported secret key scheme")
}

var _ EntityKeySchemeInstance = &EntityKey_IBE_Params_BN256{}

type EntityKey_IBE_Params_BN256 struct {
	SerdesForm *serdes.EntityPublicKey
	PublicKey  *ibe.MasterPublicKey
}

func (ek *EntityKey_IBE_Params_BN256) Supported() bool {
	return true
}
func (ek *EntityKey_IBE_Params_BN256) IdentifyingBlob(ctx context.Context) (string, error) {
	ba, err := ek.PublicKey.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal")
	}
	return string(ba), nil
}
func (ek *EntityKey_IBE_Params_BN256) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	x := ek.SerdesForm.Key.Content.(serdes.EntityParamsIBE_BN256)
	return KECCAK256.Instance(x).MultihashString(), nil
}
func (ek *EntityKey_IBE_Params_BN256) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntityKey_IBE_Params_BN256) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform certifications")
}
func (ek *EntityKey_IBE_Params_BN256) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform attestations")
}
func (k *EntityKey_IBE_Params_BN256) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	id, ok := identity.([]byte)
	if !ok {
		return nil, fmt.Errorf("only []byte identities are supported")
	}
	ch := serdes.EntityPublicIBE_BN256{
		Params: k.SerdesForm.Key.Content.(serdes.EntityParamsIBE_BN256),
		ID:     id,
	}
	cf := serdes.EntityPublicKey{
		//The child key inherits the capabilities from the parent
		Capabilities: k.SerdesForm.Capabilities,
		Key:          asn1.NewExternal(ch),
	}
	return &EntityKey_IBE_BN256{SerdesForm: &cf, Params: k.PublicKey, ID: id}, nil
}
func (ek *EntityKey_IBE_Params_BN256) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform signing")
}
func (ek *EntityKey_IBE_Params_BN256) EncryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (ek *EntityKey_IBE_Params_BN256) CanonicalForm() *serdes.EntityPublicKey {
	return ek.SerdesForm
}

func (ek *EntityKey_IBE_Params_BN256) GobEncode() ([]byte, error) {
	pubkey, err := ek.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntityKey_IBE_Params_BN256) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityPublicKey{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}

	ek.PublicKey = &ibe.MasterPublicKey{}
	err = ek.PublicKey.UnmarshalBinary(marshald)
	if err != nil {
		return err
	}
	return nil
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_IBE_Master_BN256{}

type EntitySecretKey_IBE_Master_BN256 struct {
	SerdesForm *serdes.EntityKeyringEntry
	PrivateKey *ibe.MasterPrivateKey
	PublicKey  *ibe.MasterPublicKey
}

func (ek *EntitySecretKey_IBE_Master_BN256) Supported() bool {
	return true
}
func (ek *EntitySecretKey_IBE_Master_BN256) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (ek *EntitySecretKey_IBE_Master_BN256) CanonicalForm() *serdes.EntityPublicKey {
	return &ek.SerdesForm.Public
}
func (ek *EntitySecretKey_IBE_Master_BN256) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return ek.SerdesForm
}
func (ek *EntitySecretKey_IBE_Master_BN256) DecryptMessage(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot decrypt directly (generate a child key)")
}
func (ek *EntitySecretKey_IBE_Master_BN256) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	id, ok := identity.([]byte)
	if !ok {
		return nil, fmt.Errorf("this key only supports []byte identities")
	}
	privkey := ibe.Extract(ek.PrivateKey, id)
	if privkey == nil {
		return nil, fmt.Errorf("something is wrong with this key")
	}
	c := ibe.Ciphertext{}
	err := c.UnmarshalBinary(ciphertext)
	if err != nil {
		return nil, err
	}
	content, ok := ibe.Decrypt(privkey, c)
	if !ok {
		return nil, fmt.Errorf("message failed to decrypt")
	}
	return content, nil
}
func (ek *EntitySecretKey_IBE_Master_BN256) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	id, ok := identity.([]byte)
	if !ok {
		return nil, fmt.Errorf("this key only supports []byte identities")
	}
	privkey := ibe.Extract(ek.PrivateKey, id)
	if privkey == nil {
		return nil, fmt.Errorf("something is wrong with this key")
	}
	privblob, err := privkey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("something is wrong with this key")
	}
	publicCF := serdes.EntityPublicIBE_BN256{
		Params: ek.SerdesForm.Public.Key.Content.(serdes.EntityParamsIBE_BN256),
		ID:     id,
	}
	cf := &serdes.EntityKeyringEntry{
		Public: serdes.EntityPublicKey{
			//inherit
			Capabilities: ek.SerdesForm.Public.Capabilities,
			Key:          asn1.NewExternal(publicCF),
		},
		Private: asn1.NewExternal(serdes.EntitySecretIBE_BN256(privblob)),
	}
	return &EntitySecretKey_IBE_BN256{
		SerdesForm: cf,
		Params:     ek.PublicKey,
		PrivateKey: privkey,
		ID:         id,
	}, nil
}
func (ek *EntitySecretKey_IBE_Master_BN256) Public() EntityKeySchemeInstance {
	return &EntityKey_IBE_Params_BN256{
		SerdesForm: &ek.SerdesForm.Public,
		PublicKey:  ek.PublicKey,
	}
}
func (ek *EntitySecretKey_IBE_Master_BN256) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_IBE_Master_BN256)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Private.Bytes, ekrhs.SerdesForm.Private.Bytes)
}
func (ek *EntitySecretKey_IBE_Master_BN256) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform signing")
}
func (ek *EntitySecretKey_IBE_Master_BN256) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform certification")
}
func (ek *EntitySecretKey_IBE_Master_BN256) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform attestation")
}
func (ek *EntitySecretKey_IBE_Master_BN256) GobEncode() ([]byte, error) {
	pubkey, err := ek.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	privkey, err := ek.PrivateKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(privkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntitySecretKey_IBE_Master_BN256) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityKeyringEntry{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshaldpub := make([]byte, 0)
	err = dec.Decode(&marshaldpub)
	if err != nil {
		return err
	}
	marshaldpriv := make([]byte, 0)
	err = dec.Decode(&marshaldpriv)
	if err != nil {
		return err
	}
	ek.PublicKey = &ibe.MasterPublicKey{}
	err = ek.PublicKey.UnmarshalBinary(marshaldpub)
	if err != nil {
		return err
	}
	ek.PrivateKey = &ibe.MasterPrivateKey{}
	err = ek.PrivateKey.UnmarshalBinary(marshaldpriv)
	if err != nil {
		return err
	}
	return nil
}

var _ EntityKeySchemeInstance = &EntityKey_IBE_BN256{}

type EntityKey_IBE_BN256 struct {
	SerdesForm *serdes.EntityPublicKey
	Params     *ibe.MasterPublicKey
	ID         []byte
}

func (k *EntityKey_IBE_BN256) Supported() bool {
	return true
}
func (k *EntityKey_IBE_BN256) IdentifyingBlob(ctx context.Context) (string, error) {
	js, err := k.Params.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("could not marshal")
	}
	return string(js) + "/" + string(k.ID), nil
}
func (k *EntityKey_IBE_BN256) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	params, _ := k.Params.MarshalBinary()
	return KECCAK256.Instance(params).MultihashString(), nil
}
func (k *EntityKey_IBE_BN256) HasCapability(c Capability) bool {
	for _, has := range k.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntityKey_IBE_BN256) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_IBE_BN256) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_IBE_BN256) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_IBE_BN256) EncryptMessage(ctx context.Context, content []byte) ([]byte, error) {
	ciphertext := ibe.Encrypt(rand.Reader, k.Params, k.ID, content)
	return ciphertext.MarshalBinary()
}
func (k *EntityKey_IBE_BN256) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (k *EntityKey_IBE_BN256) CanonicalForm() *serdes.EntityPublicKey {
	return k.SerdesForm
}

func (ek *EntityKey_IBE_BN256) GobEncode() ([]byte, error) {
	pubkey, err := ek.Params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(ek.ID)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntityKey_IBE_BN256) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityPublicKey{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}
	err = dec.Decode(&ek.ID)
	if err != nil {
		return err
	}
	ek.Params = &ibe.MasterPublicKey{}
	err = ek.Params.UnmarshalBinary(marshald)
	if err != nil {
		return err
	}
	return nil
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_IBE_BN256{}

type EntitySecretKey_IBE_BN256 struct {
	SerdesForm *serdes.EntityKeyringEntry
	PrivateKey *ibe.IdentityPrivateKey
	Params     *ibe.MasterPublicKey
	ID         []byte
}

func (ek *EntitySecretKey_IBE_BN256) Supported() bool {
	return true
}
func (ek *EntitySecretKey_IBE_BN256) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntitySecretKey_IBE_BN256) CanonicalForm() *serdes.EntityPublicKey {
	return &k.SerdesForm.Public
}
func (k *EntitySecretKey_IBE_BN256) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return k.SerdesForm
}
func (k *EntitySecretKey_IBE_BN256) DecryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error) {
	c := ibe.Ciphertext{}
	err := c.UnmarshalBinary(ciphertext)
	if err != nil {
		return nil, err
	}
	content, ok := ibe.Decrypt(k.PrivateKey, c)
	if !ok {
		return nil, fmt.Errorf("message failed to decrypt")
	}
	return content, nil
}
func (ek *EntitySecretKey_IBE_BN256) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (k *EntitySecretKey_IBE_BN256) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	return nil, fmt.Errorf("this key cannot generate child keys")
}
func (k *EntitySecretKey_IBE_BN256) Public() EntityKeySchemeInstance {
	return &EntityKey_IBE_BN256{
		SerdesForm: &k.SerdesForm.Public,
		Params:     k.Params,
		ID:         k.ID,
	}
}
func (ek *EntitySecretKey_IBE_BN256) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_IBE_BN256)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Public.Key.Bytes, ekrhs.SerdesForm.Public.Key.Bytes)
}
func (k *EntitySecretKey_IBE_BN256) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_IBE_BN256) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_IBE_BN256) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}

func (ek *EntitySecretKey_IBE_BN256) GobEncode() ([]byte, error) {
	pubkey, err := ek.Params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	privkey, err := ek.PrivateKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(ek.ID)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(privkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntitySecretKey_IBE_BN256) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityKeyringEntry{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}
	err = dec.Decode(&ek.ID)
	if err != nil {
		return err
	}
	marshaldpriv := make([]byte, 0)
	err = dec.Decode(&marshaldpriv)
	if err != nil {
		return err
	}
	ek.Params = &ibe.MasterPublicKey{}
	err = ek.Params.UnmarshalBinary(marshald)
	if err != nil {
		return err
	}
	ek.PrivateKey = &ibe.IdentityPrivateKey{}
	err = ek.PrivateKey.UnmarshalBinary(marshaldpriv)
	if err != nil {
		return err
	}
	return nil
}

var _ EntityKeySchemeInstance = &EntityKey_OAQUE_BN256_S20_Params{}

type EntityKey_OAQUE_BN256_S20_Params struct {
	SerdesForm *serdes.EntityPublicKey
	Params     *oaque.Params
}

func (k *EntityKey_OAQUE_BN256_S20_Params) Supported() bool {
	return true
}
func (k *EntityKey_OAQUE_BN256_S20_Params) IdentifyingBlob(ctx context.Context) (string, error) {
	ba := k.Params.Marshal()
	return string(ba), nil
}
func (k *EntityKey_OAQUE_BN256_S20_Params) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	params := k.Params.Marshal()
	return KECCAK256.Instance(params).MultihashString(), nil
}
func (k *EntityKey_OAQUE_BN256_S20_Params) HasCapability(c Capability) bool {
	for _, has := range k.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntityKey_OAQUE_BN256_S20_Params) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20_Params) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20_Params) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20_Params) EncryptMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot perform encryption")
}
func (k *EntityKey_OAQUE_BN256_S20_Params) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	id, ok := identity.([][]byte)
	if !ok {
		return nil, fmt.Errorf("only [][]byte identities are supported")
	}
	if len(id) != 20 {
		fmt.Printf("A\n")
		panic(id)
		return nil, fmt.Errorf("only 20 slot identities are supported")
	}
	ch := serdes.EntityPublicOAQUE_BN256_s20{
		Params:       k.SerdesForm.Key.Content.(serdes.EntityParamsOQAUE_BN256_s20),
		AttributeSet: id,
	}
	cf := serdes.EntityPublicKey{
		Capabilities: k.SerdesForm.Capabilities,
		Key:          asn1.NewExternal(ch),
	}
	return &EntityKey_OAQUE_BN256_S20{SerdesForm: &cf, Params: k.Params, AttributeSet: id}, nil
}
func (k *EntityKey_OAQUE_BN256_S20_Params) CanonicalForm() *serdes.EntityPublicKey {
	return k.SerdesForm
}

func (ek *EntityKey_OAQUE_BN256_S20_Params) GobEncode() ([]byte, error) {
	pubkey := ek.Params.Marshal()

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntityKey_OAQUE_BN256_S20_Params) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityPublicKey{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}

	ek.Params = &oaque.Params{}
	ok := ek.Params.Unmarshal(marshald)
	if !ok {
		return fmt.Errorf("failed to unmarshal")
	}
	return nil
}

func aesGCMEncrypt(key []byte, blob []byte, nonce []byte) []byte {
	if len(key) != 16 {
		panic("expected AES128 key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, blob, nil)
	return ciphertext
}
func aesGCMDecrypt(key []byte, ciphertext []byte, nonce []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

var _ EntityKeySchemeInstance = &EntityKey_OAQUE_BN256_S20{}

type EntityKey_OAQUE_BN256_S20 struct {
	SerdesForm   *serdes.EntityPublicKey
	Params       *oaque.Params
	AttributeSet [][]byte
}

func (k *EntityKey_OAQUE_BN256_S20) Supported() bool {
	return true
}
func (k *EntityKey_OAQUE_BN256_S20) IdentifyingBlob(ctx context.Context) (string, error) {
	ba := k.Params.Marshal()
	subid := bytes.Join(k.AttributeSet, []byte(","))
	return string(ba) + "/" + string(subid), nil
}
func (k *EntityKey_OAQUE_BN256_S20) SystemIdentifyingBlob(ctx context.Context) (string, error) {
	params := k.Params.Marshal()
	return KECCAK256.Instance(params).MultihashString(), nil
}
func (k *EntityKey_OAQUE_BN256_S20) HasCapability(c Capability) bool {
	for _, has := range k.SerdesForm.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntityKey_OAQUE_BN256_S20) VerifyCertify(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20) VerifyAttestation(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20) VerifyMessage(ctx context.Context, data []byte, signature []byte) error {
	return fmt.Errorf("this key cannot perform verification")
}
func (k *EntityKey_OAQUE_BN256_S20) EncryptMessage(ctx context.Context, content []byte) ([]byte, error) {
	sharedSecret, groupElement := cryptutils.GenerateKey(make([]byte, 16+12))
	aesk := sharedSecret[:16]
	nonce := sharedSecret[16:]
	innerciphertext := aesGCMEncrypt(aesk, content, nonce)
	al := slotsToAttrMap(k.AttributeSet)
	oaqueciphertext, err := oaque.Encrypt(nil, k.Params, al, groupElement)
	if err != nil {
		return nil, fmt.Errorf("oaque encryption failure")
	}
	oaqueciphertextBA := oaqueciphertext.Marshal()
	rv := make([]byte, 2, 2+len(oaqueciphertextBA)+len(innerciphertext))
	if len(oaqueciphertextBA) > 65535 {
		panic("oaque ciphertext too large")
	}
	binary.BigEndian.PutUint16(rv[0:2], uint16(len(oaqueciphertextBA)))
	rv = append(rv, oaqueciphertextBA...)
	rv = append(rv, innerciphertext...)
	return rv, nil
}
func (k *EntityKey_OAQUE_BN256_S20) GenerateChildKey(ctx context.Context, identity interface{}) (EntityKeySchemeInstance, error) {
	id, ok := identity.([][]byte)
	if !ok {
		return nil, fmt.Errorf("only [][]byte identities are supported")
	}
	if len(id) != 20 {
		fmt.Printf("B\n")
		return nil, fmt.Errorf("only 20 slot identities are supported")
	}
	for idx, slot := range id {
		if len(k.AttributeSet[idx]) > 0 {
			if !bytes.Equal(k.AttributeSet[idx], slot) {
				return nil, fmt.Errorf("child keys can only be MORE qualified")
			}
		}
	}
	ch := serdes.EntityPublicOAQUE_BN256_s20{
		Params:       k.SerdesForm.Key.Content.(serdes.EntityPublicOAQUE_BN256_s20).Params,
		AttributeSet: id,
	}
	cf := serdes.EntityPublicKey{
		Capabilities: k.SerdesForm.Capabilities,
		Key:          asn1.NewExternal(ch),
	}
	return &EntityKey_OAQUE_BN256_S20{SerdesForm: &cf, Params: k.Params, AttributeSet: id}, nil
}
func (k *EntityKey_OAQUE_BN256_S20) CanonicalForm() *serdes.EntityPublicKey {
	return k.SerdesForm
}

func (ek *EntityKey_OAQUE_BN256_S20) GobEncode() ([]byte, error) {
	pubkey := ek.Params.Marshal()

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(ek.AttributeSet)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntityKey_OAQUE_BN256_S20) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityPublicKey{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}
	err = dec.Decode(&ek.AttributeSet)
	if err != nil {
		return err
	}
	ek.Params = &oaque.Params{}
	ok := ek.Params.Unmarshal(marshald)
	if !ok {
		return fmt.Errorf("failed to unmarshal")
	}
	return nil
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_OAQUE_BN256_S20{}

type EntitySecretKey_OAQUE_BN256_S20 struct {
	SerdesForm   *serdes.EntityKeyringEntry
	PrivateKey   *oaque.PrivateKey
	Params       *oaque.Params
	AttributeSet [][]byte
	idhash       *[32]byte
}

func (ek *EntitySecretKey_OAQUE_BN256_S20) Supported() bool {
	return true
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntitySecretKey_OAQUE_BN256_S20) CanonicalForm() *serdes.EntityPublicKey {
	return &k.SerdesForm.Public
}
func (k *EntitySecretKey_OAQUE_BN256_S20) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return k.SerdesForm
}
func (k *EntitySecretKey_OAQUE_BN256_S20) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	id, ok := identity.([][]byte)
	if !ok {
		return nil, fmt.Errorf("only [][]byte identities are supported")
	}
	if len(id) != 20 {
		fmt.Printf("C\n")
		return nil, fmt.Errorf("only 20 slot identities are supported")
	}
	for idx, slot := range id {
		if len(k.AttributeSet[idx]) > 0 {
			if !bytes.Equal(k.AttributeSet[idx], slot) {
				return nil, fmt.Errorf("child keys can only be MORE qualified")
			}
		}
	}
	al := slotsToAttrMap(id)
	privkey := oaque.NonDelegableKey(k.Params, k.PrivateKey, al)
	if len(ciphertext) < 18 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextLength := int(binary.BigEndian.Uint16(ciphertext[0:2]))
	if len(ciphertext) < oaqueCiphertextLength+2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextBA := ciphertext[2 : oaqueCiphertextLength+2]
	ct := oaque.Ciphertext{}
	ok = ct.Unmarshal(oaqueCiphertextBA)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	groupEl := oaque.Decrypt(privkey, &ct)
	sharedSecret := cryptutils.GTToSecretKey(groupEl, make([]byte, 16+12))
	aesk := sharedSecret[:16]
	nonce := sharedSecret[16:]
	innerPlaintext, ok := aesGCMDecrypt(aesk, ciphertext[oaqueCiphertextLength+2:], nonce)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt")
	}
	return innerPlaintext, nil
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_OAQUE_BN256_S20)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Public.Key.Bytes, ekrhs.SerdesForm.Public.Key.Bytes)
}
func (k *EntitySecretKey_OAQUE_BN256_S20) DecryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 18 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextLength := int(binary.BigEndian.Uint16(ciphertext[0:2]))
	if len(ciphertext) < oaqueCiphertextLength+2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextBA := ciphertext[2 : oaqueCiphertextLength+2]
	ct := oaque.Ciphertext{}
	ok := ct.Unmarshal(oaqueCiphertextBA)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	groupEl := oaque.Decrypt(k.PrivateKey, &ct)
	sharedSecret := cryptutils.GTToSecretKey(groupEl, make([]byte, 16+12))
	aesk := sharedSecret[:16]
	nonce := sharedSecret[16:]
	innerPlaintext, ok := aesGCMDecrypt(aesk, ciphertext[oaqueCiphertextLength+2:], nonce)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt")
	}
	return innerPlaintext, nil
}

func slotsToAttrMap(id [][]byte) oaque.AttributeList {
	rv := make(map[oaque.AttributeIndex]*big.Int)
	for index, arr := range id {
		if len(arr) > 0 {
			digest := sha256.Sum256(arr)
			bigint := new(big.Int).SetBytes(digest[:])
			bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
			bigint.Add(bigint, big.NewInt(1))
			rv[oaque.AttributeIndex(index)] = bigint
		}
	}
	return rv
}

func (k *EntitySecretKey_OAQUE_BN256_S20) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	id, ok := identity.([][]byte)
	if !ok {
		return nil, fmt.Errorf("only [][]byte identities are supported")
	}
	if len(id) != 20 {
		fmt.Printf("D\n")
		return nil, fmt.Errorf("only 20 slot identities are supported")
	}
	for idx, slot := range id {
		if len(k.AttributeSet[idx]) > 0 {
			if !bytes.Equal(k.AttributeSet[idx], slot) {
				return nil, fmt.Errorf("child keys can only be MORE qualified")
			}
		}
	}
	al := slotsToAttrMap(id)
	privkey, err := oaque.QualifyKey(nil, k.Params, k.PrivateKey, al)
	if err != nil {
		return nil, err
	}
	privblob := privkey.Marshal()
	childparams := serdes.EntityParamsOQAUE_BN256_s20(k.Params.Marshal())
	publicCF := serdes.EntityPublicOAQUE_BN256_s20{
		Params:       childparams,
		AttributeSet: id,
	}
	cf := &serdes.EntityKeyringEntry{
		Public: serdes.EntityPublicKey{
			Capabilities: k.SerdesForm.Public.Capabilities,
			Key:          asn1.NewExternal(publicCF),
		},
		Private: asn1.NewExternal(serdes.EntitySecretOQAUE_BN256_s20(privblob)),
	}
	return &EntitySecretKey_OAQUE_BN256_S20{
		SerdesForm:   cf,
		Params:       k.Params,
		PrivateKey:   privkey,
		AttributeSet: id,
	}, nil
}
func (k *EntitySecretKey_OAQUE_BN256_S20) Public() EntityKeySchemeInstance {
	return &EntityKey_OAQUE_BN256_S20{
		SerdesForm:   &k.SerdesForm.Public,
		Params:       k.Params,
		AttributeSet: k.AttributeSet,
	}
}

func (k *EntitySecretKey_OAQUE_BN256_S20) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_OAQUE_BN256_S20) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_OAQUE_BN256_S20) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) GobEncode() ([]byte, error) {

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if ek.SerdesForm != nil {
		err := enc.Encode(ek.SerdesForm)
		if err != nil {
			return nil, err
		}
	} else {
		enc.Encode(&serdes.EntityKeyringEntry{})
	}
	pubkey := ek.Params.Marshal()
	err := enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(ek.AttributeSet)
	if err != nil {
		return nil, err
	}
	privkey := ek.PrivateKey.Marshal()
	err = enc.Encode(privkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityKeyringEntry{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}
	err = dec.Decode(&ek.AttributeSet)
	if err != nil {
		return err
	}
	marshaldpriv := make([]byte, 0)
	err = dec.Decode(&marshaldpriv)
	if err != nil {
		return err
	}
	if len(marshald) > 0 {
		ek.Params = &oaque.Params{}
		ok := ek.Params.Unmarshal(marshald)
		if !ok {
			return fmt.Errorf("failed to unmarshal")
		}
	}
	ek.PrivateKey = &oaque.PrivateKey{}
	ek.PrivateKey.Unmarshal(marshaldpriv)
	return nil
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) Slots() [][]byte {
	return ek.AttributeSet
}
func (ek *EntitySecretKey_OAQUE_BN256_S20) IdHash() [32]byte {
	if ek.idhash == nil {
		h := sha3.New256()
		h.Write(ek.PrivateKey.Marshal())
		res := [32]byte{}
		rslice := h.Sum(nil)
		copy(res[:], rslice)
		ek.idhash = &res
	}
	return *ek.idhash
}

var _ EntitySecretKeySchemeInstance = &EntitySecretKey_OAQUE_BN256_S20_Master{}

type EntitySecretKey_OAQUE_BN256_S20_Master struct {
	SerdesForm *serdes.EntityKeyringEntry
	PrivateKey *oaque.MasterKey
	Params     *oaque.Params
}

func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) Supported() bool {
	return true
}
func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) HasCapability(c Capability) bool {
	for _, has := range ek.SerdesForm.Public.Capabilities {
		if has == int(c) {
			return true
		}
	}
	return false
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) CanonicalForm() *serdes.EntityPublicKey {
	return &k.SerdesForm.Public
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) SecretCanonicalForm() *serdes.EntityKeyringEntry {
	return k.SerdesForm
}
func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) DecryptMessageAsChild(ctx context.Context, ciphertext []byte, identity interface{}) ([]byte, error) {
	return ek.DecryptMessage(ctx, ciphertext)
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) DecryptMessage(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 18 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextLength := int(binary.BigEndian.Uint16(ciphertext[0:2]))
	if len(ciphertext) < oaqueCiphertextLength+2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	oaqueCiphertextBA := ciphertext[2 : oaqueCiphertextLength+2]
	ct := oaque.Ciphertext{}
	ok := ct.Unmarshal(oaqueCiphertextBA)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	groupEl := oaque.DecryptWithMaster(k.PrivateKey, &ct)
	sharedSecret := cryptutils.GTToSecretKey(groupEl, make([]byte, 16+12))
	aesk := sharedSecret[:16]
	nonce := sharedSecret[16:]
	innerPlaintext, ok := aesGCMDecrypt(aesk, ciphertext[oaqueCiphertextLength+2:], nonce)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt")
	}
	return innerPlaintext, nil
}
func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) Equal(rhs EntitySecretKeySchemeInstance) bool {
	ekrhs, ok := rhs.(*EntitySecretKey_OAQUE_BN256_S20_Master)
	if !ok {
		return false
	}
	return bytes.Equal(ek.SerdesForm.Private.Bytes, ekrhs.SerdesForm.Private.Bytes)
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) GenerateChildSecretKey(ctx context.Context, identity interface{}) (EntitySecretKeySchemeInstance, error) {
	id, ok := identity.([][]byte)
	if !ok {
		return nil, fmt.Errorf("only [][]byte identities are supported")
	}
	if len(id) != 20 {
		fmt.Printf("E\n")
		return nil, fmt.Errorf("only 20 slot identities are supported")
	}
	al := slotsToAttrMap(id)
	privkey, err := oaque.KeyGen(nil, k.Params, k.PrivateKey, al)
	if err != nil {
		return nil, err
	}
	privblob := privkey.Marshal()

	publicCF := serdes.EntityPublicOAQUE_BN256_s20{
		Params:       k.SerdesForm.Public.Key.Content.(serdes.EntityParamsOQAUE_BN256_s20),
		AttributeSet: id,
	}
	cf := &serdes.EntityKeyringEntry{
		Public: serdes.EntityPublicKey{
			Capabilities: k.SerdesForm.Public.Capabilities,
			Key:          asn1.NewExternal(publicCF),
		},
		Private: asn1.NewExternal(serdes.EntitySecretOQAUE_BN256_s20(privblob)),
	}
	return &EntitySecretKey_OAQUE_BN256_S20{
		SerdesForm:   cf,
		Params:       k.Params,
		PrivateKey:   privkey,
		AttributeSet: id,
	}, nil
}

func (k *EntitySecretKey_OAQUE_BN256_S20_Master) Public() EntityKeySchemeInstance {
	return &EntityKey_OAQUE_BN256_S20_Params{
		SerdesForm: &k.SerdesForm.Public,
		Params:     k.Params,
	}
}

func (k *EntitySecretKey_OAQUE_BN256_S20_Master) SignMessage(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) SignCertify(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}
func (k *EntitySecretKey_OAQUE_BN256_S20_Master) SignAttestation(ctx context.Context, content []byte) ([]byte, error) {
	return nil, fmt.Errorf("this key cannot sign")
}

func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) GobEncode() ([]byte, error) {
	pubkey := ek.Params.Marshal()
	privkey := ek.PrivateKey.Marshal()
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(ek.SerdesForm)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(pubkey)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(privkey)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (ek *EntitySecretKey_OAQUE_BN256_S20_Master) GobDecode(ba []byte) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf)
	ek.SerdesForm = &serdes.EntityKeyringEntry{}
	err := dec.Decode(ek.SerdesForm)
	if err != nil {
		return err
	}
	marshald := make([]byte, 0)
	err = dec.Decode(&marshald)
	if err != nil {
		return err
	}
	marshaldpriv := make([]byte, 0)
	err = dec.Decode(&marshaldpriv)
	if err != nil {
		return err
	}
	ek.Params = &oaque.Params{}
	ok := ek.Params.Unmarshal(marshald)
	if !ok {
		return fmt.Errorf("failed to unmarshal")
	}
	ek.PrivateKey = &oaque.MasterKey{}
	ok = ek.PrivateKey.Unmarshal(marshaldpriv)
	if !ok {
		return fmt.Errorf("failed to unmarshal")
	}

	return nil
}
