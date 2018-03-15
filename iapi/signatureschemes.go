package iapi

import (
	"bytes"
	"context"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"golang.org/x/crypto/ed25519"
)

func OuterSignatureBindingSchemeFor(e *asn1.External) OuterSignatureBindingScheme {
	_, ok := e.Content.(serdes.SignedOuterKey)
	if ok {
		return &OuterSignatureBindingScheme_SignedOuterKey{}
	}
	return &UnsupportedOuterSignatureBindingScheme{}
}

var _ OuterSignatureBindingScheme = &OuterSignatureBindingScheme_SignedOuterKey{}

type OuterSignatureBindingScheme_SignedOuterKey struct {
}

func (sbs *OuterSignatureBindingScheme_SignedOuterKey) Supported() bool {
	return true
}

func (sbs *OuterSignatureBindingScheme_SignedOuterKey) VerifyBinding(ctx context.Context, att *Attestation, attester *Entity) wve.WVE {
	if attester == nil {
		panic("nil attester")
	}
	if att == nil {
		panic("nil attestation")
	}
	//At this time we only know how to extract the key from an ed25519 outer signature
	cform := att.CanonicalForm
	osig, ok := cform.OuterSignature.Content.(serdes.Ed25519OuterSignature)
	if !ok {
		return wve.Err(wve.UnsupportedSignatureScheme, "unknown outer signature type")
	}

	binding, ok := att.DecryptedBody.VerifierBody.OuterSignatureBinding.Content.(serdes.SignedOuterKey)
	if !ok {
		return wve.Err(wve.UnsupportedSignatureScheme, "this is not really a signed outer key")
	}
	tbsDER, err := asn1.Marshal(binding.TBS)
	if err != nil {
		panic(err)
	}
	uerr := attester.VerifyingKey.VerifyCertify(ctx, tbsDER, binding.Signature)
	if uerr != nil {
		return wve.Err(wve.InvalidSignature, "outer signature binding invalid")
	}

	//Now we know the binding is valid, check the key is the same
	if !binding.TBS.OuterSignatureScheme.Equal(serdes.EphemeralEd25519OID) {
		return wve.Err(wve.InvalidSignature, "outer signature scheme invalid")
	}

	if !bytes.Equal(binding.TBS.VerifyingKey, osig.VerifyingKey) {
		return wve.Err(wve.InvalidSignature, "bound key does not match")
	}

	//We don't actually check if the outer signature is valid, just that it is bound correctly
	return nil
}

var _ OuterSignatureBindingScheme = &UnsupportedOuterSignatureBindingScheme{}

type UnsupportedOuterSignatureBindingScheme struct {
}

func (sbs *UnsupportedOuterSignatureBindingScheme) Supported() bool {
	return false
}
func (sbs *UnsupportedOuterSignatureBindingScheme) VerifyBinding(ctx context.Context, att *Attestation, attester *Entity) wve.WVE {
	panic("VerifyBinding called on unsupported binding scheme")
}

func OuterSignatureSchemeFor(e *asn1.External) OuterSignatureScheme {
	_, ok := e.Content.(serdes.Ed25519OuterSignature)
	if ok {
		return &OuterSignatureScheme_EphemeralEd25519{}
	}
	return &UnsupportedOuterSignatureScheme{}
}

type UnsupportedOuterSignatureScheme struct {
}

func (os *UnsupportedOuterSignatureScheme) Supported() bool {
	return false
}
func (os *UnsupportedOuterSignatureScheme) VerifySignature(ctx context.Context, canonicalForm *serdes.WaveAttestation) wve.WVE {
	panic("Verify signature called on unsupported outer signature scheme")
}

type OuterSignatureScheme_EphemeralEd25519 struct {
}

func (os *OuterSignatureScheme_EphemeralEd25519) Supported() bool {
	return true
}
func (os *OuterSignatureScheme_EphemeralEd25519) VerifySignature(ctx context.Context, canonicalForm *serdes.WaveAttestation) wve.WVE {
	osig, ok := canonicalForm.OuterSignature.Content.(serdes.Ed25519OuterSignature)
	if !ok {
		return wve.Err(wve.InvalidSignature, "Outer signature lied about its scheme")
	}
	tbs, err := asn1.Marshal(canonicalForm.TBS)
	if err != nil {
		panic(err)
	}
	vk := osig.VerifyingKey
	if !ed25519.Verify(vk, tbs, osig.Signature) {
		return wve.Err(wve.InvalidSignature, "Attestation outer signature incorrect")
	}
	return nil
}
