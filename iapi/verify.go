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
	Policy  *RTreePolicy
	Expires time.Time
}

func VerifyRTreeProof(ctx context.Context, p *PVerifyRTreeProof) (*RVerifyRTreeProof, wve.WVE) {
	wwo := serdes.WaveWireObject{}
	rest, err := asn1.Unmarshal(p.DER, &wwo.Content)
	if err != nil {
		return nil, wve.Err(wve.ProofInvalid, "asn1 is malformed")
	}
	exp, ok := wwo.Content.Content.(serdes.WaveExplicitProof)
	if !ok {
		return nil, wve.Err(wve.ProofInvalid, "object is not a proof")
	}
	expiry := time.Now()
	expiryset := false
	mapping := make(map[int]*Attestation)
	for idx, atst := range exp.Attestations {
		dctx := NewKeyPoolDecryptionContext()
		for _, k := range atst.Keys {
			vfk, ok := k.Content.(serdes.AVKeyAES128GCM)
			if ok {
				dctx.SetWR1VerifierBodyKey([]byte(vfk))
				break
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
    //TODO verify the entities are ok. This needs the engine, but we don't
    //have a perspective.
		//TODO verify the attestation more
	}

	//Now verify the paths
  for 
}
