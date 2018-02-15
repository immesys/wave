package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"

	"github.com/immesys/wave/serdes"
)

type PCreateAttestation struct {
	Policy            PolicySchemeInstance
	HashScheme        HashScheme
	BodyScheme        AttestationBodyScheme
	EncryptionContext BodyEncryptionContext

	Attester *EntitySecrets
	Subject  *Entity
	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil *time.Time
}
type RCreateAttestation struct {
	DER []byte
}

func CreateAttestation(ctx context.Context, p *PCreateAttestation) (*RCreateAttestation, error) {
	if p.Policy == nil || p.Attester == nil || p.Subject == nil || p.BodyScheme == nil {
		return nil, fmt.Errorf("missing required parameters")
	}
	subjectHash, err := p.Subject.Hash(ctx, p.HashScheme)
	if err != nil {
		return nil, err
	}
	if !subjectHash.Supported() {
		return nil, fmt.Errorf("unknown hash scheme")
	}
	attesterHash, err := p.Attester.Entity.Hash(ctx, p.HashScheme)
	if err != nil {
		return nil, err
	}
	if !attesterHash.Supported() {
		return nil, fmt.Errorf("unknown hash scheme")
	}
	att := serdes.WaveAttestation{}
	externalSubjectHash, err := subjectHash.CanonicalForm()
	if err != nil {
		return nil, err
	}
	externalAttesterHash, err := attesterHash.CanonicalForm()
	if err != nil {
		return nil, err
	}
	att.TBS.Subject = *externalSubjectHash
	//TODO
	//att.TBS.Revocations
	//TODO
	//att.TBS.Extensions

	//Build up the body
	body := serdes.AttestationBody{}
	body.VerifierBody.Attester = *externalAttesterHash
	if p.ValidFrom != nil {
		body.VerifierBody.Validity.NotBefore = *p.ValidFrom
	} else {
		body.VerifierBody.Validity.NotBefore = time.Now()
	}
	if p.ValidUntil != nil {
		body.VerifierBody.Validity.NotAfter = *p.ValidUntil
	} else {
		body.VerifierBody.Validity.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	}
	externalPolicy, err := p.Policy.CanonicalForm(ctx)
	if err != nil {
		return nil, err
	}
	body.VerifierBody.Policy = *externalPolicy

	//Create the ephemeral key for signing
	eks, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapAttestation)
	if err != nil {
		return nil, err
	}
	ekpub, _ := eks.Public()

	outersig := serdes.Ed25519OuterSignature{}
	outersig.VerifyingKey = []byte(ekpub.(*EntityKey_Ed25519).PublicKey)

	binding := serdes.SignedOuterKey{}
	binding.TBS.OuterSignatureScheme = serdes.EphemeralEd25519OID
	binding.TBS.VerifyingKey = outersig.VerifyingKey
	bindingDER, err := asn1.Marshal(binding.TBS)
	if err != nil {
		return nil, err
	}
	//spew.Dump(p.Attester)
	sig, err := p.Attester.PrimarySigningKey().SignCertify(ctx, bindingDER)
	if err != nil {
		return nil, err
	}
	binding.Signature = sig

	body.VerifierBody.OuterSignatureBinding = asn1.NewExternal(binding)
	//This is just an intermediate form
	att.TBS.Body = asn1.NewExternal(body)

	//Now encrypt the body
	encryptedForm, err := p.BodyScheme.EncryptBody(ctx, p.EncryptionContext, &att)
	if err != nil {
		return nil, err
	}

	//Now sign it
	sigDER, err := asn1.Marshal(encryptedForm.TBS)
	if err != nil {
		return nil, err
	}

	outersig.Signature, err = eks.SignAttestation(ctx, sigDER)
	if err != nil {
		return nil, err
	}
	att.OuterSignature = asn1.NewExternal(outersig)
	wo := serdes.WaveWireObject{}
	wo.Content = asn1.NewExternal(att)
	fullDER, err := asn1.Marshal(wo.Content)
	if err != nil {
		return nil, err
	}
	return &RCreateAttestation{
		DER: fullDER,
	}, nil
}

type PParseAttestation struct {
	DER               []byte
	DecryptionContext BodyDecryptionContext
}
type RParseAttestation struct {
	Attestation *Attestation
	ExtraInfo   interface{}
}

func ParseAttestation(ctx context.Context, p *PParseAttestation) (*RParseAttestation, error) {
	wo := serdes.WaveWireObject{}
	trailing, err := asn1.Unmarshal(p.DER, &wo.Content)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %v", err)
	}
	if len(trailing) != 0 {
		return nil, fmt.Errorf("could not decode: trailing content")
	}
	att, ok := wo.Content.Content.(serdes.WaveAttestation)
	if !ok {
		return nil, fmt.Errorf("object not an attestation")
	}

	scheme := AttestationBodySchemeFor(&att.TBS.Body)
	if err != nil {
		return nil, err
	}
	decoded, extra, err := scheme.DecryptBody(ctx, p.DecryptionContext, &att)
	if err != nil {
		return nil, err
	}
	rv := Attestation{
		CanonicalForm: &att,
		DecryptedBody: decoded,
	}
	return &RParseAttestation{
		Attestation: &rv,
		ExtraInfo:   extra,
	}, nil
}
