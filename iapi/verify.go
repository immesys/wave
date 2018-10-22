package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

type PCompactProof struct {
	DER []byte
}
type RCompactProof struct {
	DER []byte
}

func CompactProof(ctx context.Context, p *PCompactProof) (*RCompactProof, wve.WVE) {
	wwo := serdes.WaveWireObject{}
	rest, err := asn1.Unmarshal(p.DER, &wwo.Content)
	if err != nil {
		return nil, wve.Err(wve.ProofInvalid, "asn1 is malformed")
	}
	if len(rest) != 0 {
		return nil, wve.Err(wve.ProofInvalid, "trailing bytes")
	}
	exp, ok := wwo.Content.Content.(serdes.WaveExplicitProof)
	if !ok {
		return nil, wve.Err(wve.ProofInvalid, "object is not a proof")
	}
	for i, _ := range exp.Attestations {
		exp.Attestations[i].Content = nil
	}
	exp.Entities = nil
	wwo.Content = asn1.NewExternal(exp)
	der, err := asn1.Marshal(wwo.Content)
	if err != nil {
		return nil, wve.ErrW(wve.InternalError, "could not marshal asn1", err)
	}
	return &RCompactProof{
		DER: der,
	}, nil
}

type PVerifySignature struct {
	DER            []byte
	Content        []byte
	Signer         HashSchemeInstance
	SignerLocation LocationSchemeInstance
	VCtx           VerificationContext
}
type RVerifySignature struct {
	Okay bool
}

func VerifySignature(ctx context.Context, p *PVerifySignature) (*RVerifySignature, wve.WVE) {
	sig := serdes.Signature{}
	rest, err := asn1.Unmarshal(p.DER, &sig)
	if err != nil {
		return nil, wve.Err(wve.ProofInvalid, "asn1 is malformed")
	}
	if len(rest) != 0 {
		return nil, wve.Err(wve.ProofInvalid, "trailing bytes")
	}
	signer, err := p.VCtx.EntityByHashLoc(ctx, p.Signer, p.SignerLocation)
	if err != nil {
		return nil, wve.ErrW(wve.LookupFailure, "could not resolve signer", err)
	}
	uerr := signer.MessageVerifyingKey().VerifyMessage(ctx, p.Content, sig.Signature)
	if uerr != nil {
		return nil, wve.ErrW(wve.InvalidSignature, "signature invalid", uerr)
	}
	return &RVerifySignature{true}, nil
}

type PVerifyRTreeProof struct {
	DER  []byte
	VCtx VerificationContext
}
type RVerifyRTreeProof struct {
	Policy          *RTreePolicy
	Expires         time.Time
	Attestations    []*Attestation
	Paths           [][]int
	Subject         HashSchemeInstance
	SubjectLocation LocationSchemeInstance
}

func VerifyRTreeProof(ctx context.Context, p *PVerifyRTreeProof) (*RVerifyRTreeProof, wve.WVE) {
	wwo := serdes.WaveWireObject{}
	rest, err := asn1.Unmarshal(p.DER, &wwo.Content)
	if err != nil {
		return nil, wve.Err(wve.ProofInvalid, "asn1 is malformed")
	}
	if len(rest) != 0 {
		return nil, wve.Err(wve.ProofInvalid, "trailing bytes")
	}
	exp, ok := wwo.Content.Content.(serdes.WaveExplicitProof)
	if !ok {
		return nil, wve.Err(wve.ProofInvalid, "object is not a proof")
	}
	expiry := time.Now()
	expiryset := false
	dctx := NewKeyPoolDecryptionContext()
	//Ensure that entity lookup gets passed through
	dctx.SetUnderlyingContext(p.VCtx)
	for _, entder := range exp.Entities {
		resp, err := ParseEntity(ctx, &PParseEntity{
			DER: entder,
		})
		if err != nil {
			return nil, wve.Err(wve.ProofInvalid, "could not parse included entity")
		}
		if !expiryset || resp.Entity.CanonicalForm.TBS.Validity.NotAfter.Before(expiry) {
			expiry = resp.Entity.CanonicalForm.TBS.Validity.NotAfter
			expiryset = true
		}
		dctx.AddEntity(resp.Entity)
	}
	mapping := make(map[int]*Attestation)
	for idx, atst := range exp.Attestations {
		if len(atst.Keys) == 0 {
			fmt.Printf("atst has no keys\n")
		}
		for _, k := range atst.Keys {
			vfk, ok := k.Content.(serdes.AVKeyAES128GCM)
			if ok {
				dctx.SetWR1VerifierBodyKey([]byte(vfk))
				break
			} else {
				fmt.Printf("ATST KEY WAS NOT AES\n")
			}
		}
		var pap *PParseAttestation
		if len(atst.Content) > 0 {
			pap = &PParseAttestation{
				DER:               atst.Content,
				DecryptionContext: dctx,
			}
		} else {
			spew.Dump(atst)
			for _, cfloc := range atst.Locations {
				fmt.Printf("trying a location\n")
				cf := cfloc
				loc := LocationSchemeInstanceFor(&cf)
				if !loc.Supported() {
					continue
				}
				hsh := HashSchemeInstanceFor(&atst.Hash)
				if !hsh.Supported() {
					continue
				}
				att, err := p.VCtx.AttestationByHashLoc(ctx, hsh, loc)
				if err != nil {
					return nil, wve.ErrW(wve.LookupFailure, "could not resolve attestation", err)
				}
				pap = &PParseAttestation{
					Attestation:       att,
					DecryptionContext: dctx,
				}
				break
			}
		}
		if pap == nil {
			return nil, wve.Err(wve.ProofInvalid, fmt.Sprintf("could not resolve attestation %d DER", idx))
		}
		rpa, err := ParseAttestation(ctx, pap)
		if err != nil {
			return nil, wve.ErrW(wve.ProofInvalid, fmt.Sprintf("could not parse attestation %d", idx), err)
		}
		if rpa.IsMalformed {
			return nil, wve.ErrW(wve.ProofInvalid, fmt.Sprintf("attestation %d is malformed", idx), err)
		}
		if rpa.Attestation.DecryptedBody == nil {
			return nil, wve.ErrW(wve.ProofInvalid, fmt.Sprintf("attestation %d is not decryptable", idx), err)
		}
		mapping[idx] = rpa.Attestation
		attExpiry := rpa.Attestation.DecryptedBody.VerifierBody.Validity.NotAfter
		if !expiryset || attExpiry.Before(expiry) {
			expiry = attExpiry
			expiryset = true
		}
	}

	//TODO revocation checks
	//todo check end to end and check all paths have same subject
	//then fill in subject here and make it get printed by cli
	//Now verify the paths
	pathpolicies := []*RTreePolicy{}
	pathEndEntities := []HashSchemeInstance{}
	var subjectLocation LocationSchemeInstance
	for _, path := range exp.Paths {
		if len(path) == 0 {
			return nil, wve.Err(wve.ProofInvalid, "path of length 0")
		}
		currAtt, ok := mapping[path[0]]
		if !ok {
			return nil, wve.Err(wve.ProofInvalid, "proof refers to non-included attestation")
		}
		cursubj, cursubloc := currAtt.Subject()
		policy, err := PolicySchemeInstanceFor(&currAtt.DecryptedBody.VerifierBody.Policy)
		if err != nil {
			return nil, wve.Err(wve.ProofInvalid, "unexpected policy error")
		}
		rtreePolicy, ok := policy.(*RTreePolicy)
		if !ok {
			return nil, wve.Err(wve.ProofInvalid, "not an RTree policy")
		}
		for _, pe := range path[1:] {
			nextAtt, ok := mapping[pe]
			if !ok {
				return nil, wve.Err(wve.ProofInvalid, "proof refers to non-included attestation")
			}
			nextAttest, _, err := nextAtt.Attester()
			if err != nil {
				return nil, wve.Err(wve.ProofInvalid, "unexpected encrypted attestation")
			}
			//fmt.Printf("pe %d current subject: \n%x\nnext attester: %x\n", pe, cursubj.Value(), nextAttest.Value())
			if !HashSchemeInstanceEqual(cursubj, nextAttest) {

				return nil, wve.Err(wve.ProofInvalid, "path has broken links")
			}
			nextPolicy, err := PolicySchemeInstanceFor(&nextAtt.DecryptedBody.VerifierBody.Policy)
			if err != nil {
				return nil, wve.Err(wve.ProofInvalid, "unexpected policy error")
			}
			nextRtreePolicy, ok := nextPolicy.(*RTreePolicy)
			if !ok {
				return nil, wve.Err(wve.ProofInvalid, "not an RTree policy")
			}
			result, okay, msg, err := rtreePolicy.Intersect(nextRtreePolicy)
			if err != nil {
				return nil, wve.Err(wve.ProofInvalid, "bad policy intersection")
			}
			if !okay {
				return nil, wve.Err(wve.ProofInvalid, fmt.Sprintf("bad policy intersection: %v", msg))
			}
			rtreePolicy = result
			currAtt = nextAtt
			cursubj, cursubloc = nextAtt.Subject()
		}
		pathpolicies = append(pathpolicies, rtreePolicy)
		pathEndEntities = append(pathEndEntities, cursubj)
		subjectLocation = cursubloc
	}

	//Now combine the policies together
	aggregatepolicy := pathpolicies[0]
	finalsubject := pathEndEntities[0]
	for idx, p := range pathpolicies[1:] {
		if !HashSchemeInstanceEqual(finalsubject, pathEndEntities[idx]) {
			return nil, wve.Err(wve.ProofInvalid, "paths don't terminate at same entity")
		}
		result, okay, msg, err := aggregatepolicy.Union(p)
		if err != nil {
			return nil, wve.Err(wve.ProofInvalid, "bad policy intersection")
		}
		if !okay {
			return nil, wve.Err(wve.ProofInvalid, fmt.Sprintf("bad policy intersection: %v", msg))
		}
		aggregatepolicy = result

	}
	rv := &RVerifyRTreeProof{
		Policy:          aggregatepolicy,
		Expires:         expiry,
		Attestations:    make([]*Attestation, len(mapping)),
		Paths:           exp.Paths,
		Subject:         finalsubject,
		SubjectLocation: subjectLocation,
	}
	for idx, att := range mapping {
		rv.Attestations[idx] = att
	}
	return rv, nil
}
