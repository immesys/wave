package iapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/immesys/asn1"

	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"github.com/ucbrise/jedi-protocol-go"
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
	err := p.Policy.CheckValid()
	if err != nil {
		return nil, wve.ErrW(wve.InvalidParameter, "policy is invalid", err)
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

	werr := checkPolicyForSpecialCases(p.Policy)
	if werr != nil {
		return nil, werr
	}
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
	if body.VerifierBody.Validity.NotAfter.Before(body.VerifierBody.Validity.NotBefore) {
		return nil, wve.Err(wve.InvalidParameter, "invalid validity times")
	}
	if body.VerifierBody.Validity.NotAfter.Add(-3 * 365 * 24 * time.Hour).After(body.VerifierBody.Validity.NotBefore) {
		return nil, wve.Err(wve.InvalidParameter, "valid range cannot exceed roughly 3 years")
	}
	attesterExpiry := p.Attester.Entity.CanonicalForm.TBS.Validity.NotAfter
	if body.VerifierBody.Validity.NotAfter.After(attesterExpiry) {
		body.VerifierBody.Validity.NotAfter = attesterExpiry
	}
	subjectExpiry := p.Subject.CanonicalForm.TBS.Validity.NotAfter
	if body.VerifierBody.Validity.NotAfter.After(subjectExpiry) {
		body.VerifierBody.Validity.NotAfter = subjectExpiry
	}
	externalPolicy := p.Policy.CanonicalForm()
	body.VerifierBody.Policy = *externalPolicy

	//Create the ephemeral key for signing
	eks, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapAttestation)
	if err != nil {
		panic(err)
	}
	ekpub := eks.Public()
	rsecret := p.Attester.Keyring[0].SecretCanonicalForm().Private.Content.(serdes.EntitySecretEd25519)
	rsecret2 := ekpub.CanonicalForm().Key.Content.(serdes.EntityPublicEd25519)

	ro := NewCommitmentRevocationSchemeInstance(p.SubjectLocation, true, rsecret, rsecret2)
	att.TBS.Revocations = append(att.TBS.Revocations, ro.CanonicalForm())

	outersig := serdes.Ed25519OuterSignature{}
	outersig.VerifyingKey = []byte(ekpub.(*EntityKey_Ed25519).PublicKey)

	binding := serdes.SignedOuterKey{}
	binding.TBS.OuterSignatureScheme = serdes.EphemeralEd25519OID
	binding.TBS.VerifyingKey = outersig.VerifyingKey
	bindingDER, err := asn1.Marshal(binding.TBS)
	if err != nil {
		panic(err)
	}
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

	// {
	// 	att, err := ParseAttestation(ctx, &PParseAttestation{
	// 		DER: rv.DER,
	// 	})
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	content, _, err := p.Attester.AttestationRevocationDetails(att.Attestation)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	hi := KECCAK256.Instance(content)
	// 	if len(att.Attestation.Revocations) == 0 {
	// 		panic("parsed attestation no revocations\n")
	// 	}
	// 	expectedHash := HashSchemeInstanceFor(&att.Attestation.Revocations[0].(*CommitmentRevocationSchemeInstance).CRBody.Hash)
	// 	if hi.MultihashString() != expectedHash.MultihashString() {
	// 		panic("att evocation mismatch")
	// 	} else {
	// 		fmt.Printf("att revocation ok\n")
	// 	}
	// }

	return rv, nil
}

func pprefixFromResource(res string, ismessage bool) ([][]byte, wve.WVE) {
	parts := strings.Split(res, "/")
	if len(parts) > 11 {
		return nil, wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt resource can not be more than 11 elements long")
	}
	pprefix := make([][]byte, 11)
	close := true
	for idx, p := range parts {
		if p == "+" {
			if ismessage {
				return nil, wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt resource should not have '+' in it when used for encryption")
			}
			continue //leave as nil
		}
		if p == "*" {
			if ismessage {
				return nil, wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt resource should not have '*' in it when used for encryption")
			}
			if idx != len(parts)-1 {
				return nil, wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt resource may only have a * as the last element")
			}
			close = false
			continue //leave as nil
		}
		if p == "" {
			return nil, wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt resource may not have empty elements")
		}
		pprefix[idx] = []byte(p)
	}
	if close {
		for i := len(parts); i < 11; i++ {
			pprefix[i] = []byte("\x00") //bottom
		}
	}
	return pprefix, nil
}

func checkPolicyForSpecialCases(p PolicySchemeInstance) wve.WVE {
	rtree, ok := p.(*RTreePolicy)
	if !ok {
		return nil
	}
	foundE2E := false
	var res string
	for _, s := range rtree.SerdesForm.Statements {
		hi := HashSchemeInstanceFor(&s.PermissionSet)
		if hi.Supported() {
			if hi.MultihashString() == consts.WaveBuiltinPSET {
				foundE2E = true
				if len(s.Permissions) == 0 {
					return wve.Err(wve.InvalidE2EEGrant, "a wave pset grant must have exactly one permission")
				}
				if len(s.Permissions) > 1 {
					return wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt grant can only have one permission and one statement")
				}
				if s.Permissions[0] != consts.WaveBuiltinE2EE {
					return wve.Err(wve.InvalidE2EEGrant, "the only valid wave pset permissions is 'decrypt'")
				}
				res = s.Resource
			} else if hi.MultihashString() == consts.JEDIBuiltinPSET {
				seen := make(map[string]struct{})
				for _, perm := range s.Permissions {
					if _, ok := seen[perm]; ok {
						return wve.Err(wve.InvalidJEDIGrant, fmt.Sprintf("permission '%s' repeats", perm))
					}

					if perm != consts.JEDIBuiltinDecrypt && perm != consts.JEDIBuiltinSign {
						return wve.Err(wve.InvalidJEDIGrant, fmt.Sprintf("the only valid JEDI grants are '%s' and '%s'", consts.JEDIBuiltinDecrypt, consts.JEDIBuiltinSign))
					}
					seen[perm] = struct{}{}
				}
				uri, err2 := jedi.ParseURI(s.Resource)
				if err2 != nil {
					return wve.Err(wve.InvalidJEDIGrant, fmt.Sprintf("Invalid URI for JEDI grant: '%s'", err2.Error()))
				}
				rtree.VisibilityURI = make([][]byte, 11)
				if len(uri) > len(rtree.VisibilityURI) {
					return wve.Err(wve.InvalidJEDIGrant, "URI is too long for a JEDI grant")
				}
				jedi.EncodeURIPathInto(uri, rtree.VisibilityURI)
			}
		}
	}
	if !foundE2E {
		return nil
	}
	if len(rtree.SerdesForm.Statements) != 1 {
		return wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt grant can only have one permission and one statement")
	}
	for _, p := range rtree.WR1PartitionPrefix(true)[1:] {
		if len(p) != 0 {
			return wve.Err(wve.InvalidE2EEGrant, "a wave:decrypt grant must have no partition specified (it is generated from the resource)")
		}
	}
	pprefix, err := pprefixFromResource(res, false)
	if err != nil {
		return err
	}
	rtree.VisibilityURI = pprefix
	return nil
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
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.UnexpectedObject, "DER is not a wave attestation")
		}
		att = &attb
	} else {
		att = p.Attestation.CanonicalForm
	}

	rv := Attestation{
		CanonicalForm: att,
	}

	for _, ro := range att.TBS.Revocations {
		sch := RevocationSchemeInstanceFor(&ro)
		rv.Revocations = append(rv.Revocations, sch)
	}

	subject, subjectLoc := rv.Subject()
	if !subject.Supported() {
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.Err(wve.UnsupportedHashScheme, "Subject hash is unsupported")
	}
	if !subjectLoc.Supported() {
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.Err(wve.UnsupportedLocationScheme, "Subject location is unsupported")
	}
	scheme := AttestationBodySchemeFor(&att.TBS.Body)
	if !scheme.Supported() {
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.Err(wve.BodySchemeError, "Unsupported body scheme")
	}

	var inextra *WR1Extra
	if p.Attestation != nil {
		inextra = p.Attestation.WR1Extra
	}

	decoded, extra, err := scheme.DecryptBody(ctx, p.DecryptionContext, att, inextra)
	if err != nil {
		fmt.Printf("failed parse5: %v %s\n", err, att.TBS.Body.OID)
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.ErrW(wve.BodySchemeError, "Failed to decrypt", err)
	}
	rv.DecryptedBody = decoded

	if decoded != nil && p.DecryptionContext != nil {
		attesterHash := HashSchemeInstanceFor(&decoded.VerifierBody.Attester)
		attesterloc := LocationSchemeInstanceFor(&decoded.VerifierBody.AttesterLocation)
		if err != nil {
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.ErrW(wve.UnknownError, "could not get attester details", err)
		}
		attester, werr := p.DecryptionContext.EntityByHashLoc(ctx, attesterHash, attesterloc)
		if werr != nil {
			return &RParseAttestation{
				IsMalformed: true,
			}, werr
		}
		if attester == nil {
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.LookupFailure, "could not resolve attesting entity")
		}
		//Check signature binding
		osigbinding := OuterSignatureBindingSchemeFor(&decoded.VerifierBody.OuterSignatureBinding)
		if !osigbinding.Supported() {
			return &RParseAttestation{
				IsMalformed: true,
			}, wve.Err(wve.UnsupportedSignatureScheme, "outer signature binding not supported")
		}
		werr = osigbinding.VerifyBinding(ctx, &rv, attester)
		if werr != nil {
			return &RParseAttestation{
				IsMalformed: true,
			}, werr
		}
	} //end if decrypted

	//Check signature
	osig := OuterSignatureSchemeFor(&att.OuterSignature)
	if !osig.Supported() {
		return &RParseAttestation{
			IsMalformed: true,
		}, wve.Err(wve.UnsupportedSignatureScheme, "outer signature not supported")
	}
	werr := osig.VerifySignature(ctx, att)
	if werr != nil {
		return &RParseAttestation{
			IsMalformed: true,
		}, werr
	}

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
func NewParsedAttestation(ctx context.Context, p *PCreateAttestation) (*RParseAttestation, wve.WVE) {
	intermediate, err := CreateAttestation(ctx, p)
	if err != nil {
		return nil, err
	}
	rv, e := ParseAttestation(ctx, &PParseAttestation{DER: intermediate.DER})

	//Test revocation matches
	{
		content, _, err := p.Attester.AttestationRevocationDetails(rv.Attestation)
		if err != nil {
			panic(err)
		}
		hi := KECCAK256.Instance(content)
		expectedHash := HashSchemeInstanceFor(&rv.Attestation.Revocations[0].(*CommitmentRevocationSchemeInstance).CRBody.Hash)
		if hi.MultihashString() != expectedHash.MultihashString() {
			panic("att evocation mismatch")
		} else {
			fmt.Printf("att revocation ok\n")
		}
	}

	return rv, e
}
