package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

type PVerifyRTreeProof struct {
	DER []byte
}
type RVerifyRTreeProof struct {
	Policy       *RTreePolicy
	Expires      time.Time
	Attestations []*Attestation
	Paths        [][]int
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
		rpa, err := ParseAttestation(ctx, &PParseAttestation{
			DER:               atst.Content,
			DecryptionContext: dctx,
		})
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

	//Now verify the paths
	pathpolicies := []*RTreePolicy{}
	for _, path := range exp.Paths {
		if len(path) == 0 {
			return nil, wve.Err(wve.ProofInvalid, "path of length 0")
		}
		firstAtt, ok := mapping[path[0]]
		if !ok {
			return nil, wve.Err(wve.ProofInvalid, "proof refers to non-included attestation")
		}
		policy, err := PolicySchemeInstanceFor(&firstAtt.DecryptedBody.VerifierBody.Policy)
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
		}
		pathpolicies = append(pathpolicies, rtreePolicy)
	}

	//Now combine the policies together
	aggregatepolicy := pathpolicies[0]
	for _, p := range pathpolicies[1:] {
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
		Policy:       aggregatepolicy,
		Expires:      expiry,
		Attestations: make([]*Attestation, len(mapping)),
		Paths:        exp.Paths,
	}
	for idx, att := range mapping {
		rv.Attestations[idx] = att
	}
	return rv, nil
}
