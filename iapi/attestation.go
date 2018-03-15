package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"

	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

type PCreateAttestation struct {
	Policy            PolicySchemeInstance
	HashScheme        HashScheme
	BodyScheme        AttestationBodyScheme
	EncryptionContext BodyEncryptionContext

	Attester         *EntitySecrets
	AttesterLocation LocationSchemeInstance

	Subject         *Entity
	SubjectLocation LocationSchemeInstance

	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil *time.Time
}
type RCreateAttestation struct {
	DER         []byte
	VerifierKey []byte
	ProverKey   []byte
}

func CreateAttestation(ctx context.Context, p *PCreateAttestation) (*RCreateAttestation, wve.WVE) {
	if p.Policy == nil || p.Attester == nil || p.Subject == nil || p.BodyScheme == nil || p.SubjectLocation == nil || p.AttesterLocation == nil {
		return nil, wve.Err(wve.MissingParameter, "missing required parameters")
	}
	if !p.HashScheme.Supported() {
		return nil, wve.Err(wve.UnsupportedHashScheme, "unsupported hash scheme")
	}
	subjectHash := p.Subject.Hash(p.HashScheme)
	if !subjectHash.Supported() {
		panic(subjectHash)
	}
	attesterHash := p.Attester.Entity.Hash(p.HashScheme)
	if !attesterHash.Supported() {
		panic(attesterHash)
	}
	att := serdes.WaveAttestation{}
	externalSubjectHash := subjectHash.CanonicalForm()
	externalAttesterHash := attesterHash.CanonicalForm()
	att.TBS.Subject = *externalSubjectHash
	subjloc := p.SubjectLocation.CanonicalForm()
	att.TBS.SubjectLocation = *subjloc

	//TODO
	//att.TBS.Revocations
	//TODO
	//att.TBS.Extensions

	//Build up the body
	body := serdes.AttestationBody{}
	body.VerifierBody.Attester = *externalAttesterHash
	attloc := p.AttesterLocation.CanonicalForm()
	body.VerifierBody.AttesterLocation = *attloc

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
	externalPolicy := p.Policy.CanonicalForm()
	body.VerifierBody.Policy = *externalPolicy

	//Create the ephemeral key for signing
	eks, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapAttestation)
	if err != nil {
		panic(err)
	}
	ekpub := eks.Public()

	outersig := serdes.Ed25519OuterSignature{}
	outersig.VerifyingKey = []byte(ekpub.(*EntityKey_Ed25519).PublicKey)

	binding := serdes.SignedOuterKey{}
	binding.TBS.OuterSignatureScheme = serdes.EphemeralEd25519OID
	binding.TBS.VerifyingKey = outersig.VerifyingKey
	bindingDER, err := asn1.Marshal(binding.TBS)
	if err != nil {
		panic(err)
	}
	//spew.Dump(p.Attester)
	sig, err := p.Attester.PrimarySigningKey().SignCertify(ctx, bindingDER)
	if err != nil {
		panic(err)
	}
	binding.Signature = sig

	body.VerifierBody.OuterSignatureBinding = asn1.NewExternal(binding)
	//This is just an intermediate form
	att.TBS.Body = asn1.NewExternal(body)

	//Now encrypt the body
	encryptedForm, extra, err := p.BodyScheme.EncryptBody(ctx, p.EncryptionContext, p.Attester, p.Subject, &att, p.Policy)
	if err != nil {
		return nil, wve.ErrW(wve.BodySchemeError, "could not encrypt", err)
	}

	//Now sign it
	sigDER, err := asn1.Marshal(encryptedForm.TBS)
	if err != nil {
		panic(err)
	}

	outersig.Signature, err = eks.SignAttestation(ctx, sigDER)
	if err != nil {
		panic(err)
	}
	att.OuterSignature = asn1.NewExternal(outersig)
	wo := serdes.WaveWireObject{}
	wo.Content = asn1.NewExternal(att)
	fullDER, err := asn1.Marshal(wo.Content)
	if err != nil {
		panic(err)
	}
	rv := &RCreateAttestation{
		DER: fullDER,
	}
	if wr1ex, ok := extra.(*WR1Extra); ok {
		rv.ProverKey = wr1ex.ProverBodyKey
		rv.VerifierKey = wr1ex.VerifierBodyKey
	}
	return rv, nil
}

type PParseAttestation struct {
	//Either specify DER or specify Attestation (to further decrypt a partially
	//decrypted DOT)
	DER               []byte
	Attestation       *Attestation
	DecryptionContext BodyDecryptionContext
}
type RParseAttestation struct {
	Attestation *Attestation
	IsMalformed bool
	ExtraInfo   interface{}
}

func ParseAttestation(ctx context.Context, p *PParseAttestation) (*RParseAttestation, wve.WVE) {
	var att *serdes.WaveAttestation
	if p.Attestation == nil {
		wo := serdes.WaveWireObject{}
		trailing, err := asn1.Unmarshal(p.DER, &wo.Content)
		if err != nil {
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.MalformedDER, "DER did not parse")
		}
		if len(trailing) != 0 {
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.MalformedDER, "DER contains trailing bytes")
		}
		var ok bool
		attb, ok := wo.Content.Content.(serdes.WaveAttestation)
		if !ok {
			fmt.Printf("failed parse3: %v\n", err)
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.UnexpectedObject, "DER is not a wave attestation")
		}
		att = &attb
	} else {
		att = p.Attestation.CanonicalForm
	}

	scheme := AttestationBodySchemeFor(&att.TBS.Body)
	if !scheme.Supported() {
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.Err(wve.BodySchemeError, "Unsupported body scheme")
	}

	decoded, extra, err := scheme.DecryptBody(ctx, p.DecryptionContext, att)
	if err != nil {
		fmt.Printf("failed parse5: %v %s\n", err, att.TBS.Body.OID)
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.ErrW(wve.BodySchemeError, "Failed to decrypt", err)
	}
	rv := Attestation{
		CanonicalForm: att,
		DecryptedBody: decoded,
	}

	//TODO Check signature
	wr1extra, ok := extra.(*WR1Extra)
	if ok {
		rv.WR1Extra = wr1extra
	}
	return &RParseAttestation{
		Attestation: &rv,
		ExtraInfo:   extra,
	}, nil
}

//This is obviously of limited use, only an Att with no encryption will fully parse
func NewParsedAttestation(ctx context.Context, p *PCreateAttestation) (*RParseAttestation, error) {
	intermediate, err := CreateAttestation(ctx, p)
	if err != nil {
		return nil, err
	}
	return ParseAttestation(ctx, &PParseAttestation{DER: intermediate.DER})
}
