package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/wave/iapi"
)

//Check for revocations
//If decoded, check for expiry and entRevoked
//This must be fairly fast as it gets called frequently on the same stuff
func (e *Engine) checkAttestationAndSave(ctx context.Context, d *iapi.Attestation, v *Validity) (bool, error) {
	fmt.Printf("check attestation: %#v\n", v)
	if v.DstInvalid || v.SrcInvalid {
		return false, e.ws.MoveAttestationEntRevokedP(e.ctx, d)
	}
	if v.Revoked {
		return false, e.ws.MoveAttestationRevokedG(e.ctx, d)
	}
	if v.Expired {
		return false, e.ws.MoveAttestationExpiredP(e.ctx, d)
	}
	return v.Valid, nil
}

func (e *Engine) checkPendingAttestationAndSave(ctx context.Context, d *iapi.Attestation, v *Validity) (bool, error) {
	fmt.Printf("check pend attestation: %#v\n", v)
	if v.DstInvalid {
		return false, e.ws.MoveAttestationEntRevokedP(e.ctx, d)
	}
	if v.Malformed {
		return false, e.ws.MoveAttestationMalformedP(e.ctx, d.Keccak256HI())
	}
	return true, nil
}

//
// func (e *Engine) checkPendingAttestationAndSave(d *iapi.Attestation) (okay bool, err error) {
// 	//Like checkDot but don't check (nonexistant) content
// 	todo
// 	subjecth, subjloc := d.Subject()
// 	subject, dstvalid, err := e.LookupEntity(context.Background(), subjecth, subjloc)
// 	if err != nil {
// 		return false, err
// 	}
// 	dstokay, err := e.checkEntityAndSave(subject, dstvalid)
// 	if err != nil {
// 		return false, e.ws.MoveAttestationEntRevokedP(e.ctx, d)
// 	}
//
// 	if !dstokay {
// 		//This dot must move to EntRevoked
// 		return false, e.ws.MoveAttestationEntRevokedP(e.ctx, d)
// 	}
// 	// if revoked {
// 	// 	return false, e.ws.MoveDotRevokedG(e.ctx, d)
// 	// }
// 	return true, nil
// }

func (e *Engine) checkEntityAndSave(ent *iapi.Entity, v *Validity) (bool, error) {
	if v.Expired {
		return false, e.ws.MoveEntityExpiredG(e.ctx, ent)
	}
	if v.Revoked {
		return false, e.ws.MoveEntityRevokedG(e.ctx, ent)
	}
	return v.Valid, nil
}

func (e *Engine) checkNameDeclarationAndSave(ctx context.Context, nd *iapi.NameDeclaration, v *Validity) (bool, error) {
	if v.Revoked {
		return false, e.ws.MoveNameDeclarationRevokedP(ctx, nd)
	}
	if v.Expired {
		return false, e.ws.MoveNameDeclarationExpiredP(ctx, nd)
	}
	if v.Valid {
		return true, nil
	}
	return false, nil
}
func (e *Engine) revoked(r iapi.RevocationSchemeInstance) (bool, error) {
	ts, err := e.ws.GetRevocationCheck(e.ctx, r.Id())
	if err != nil {
		return false, err
	}
	docheck := false
	if ts == nil {
		docheck = true
	} else {
		t := time.Unix(0, *ts)
		if t.After(time.Now().Add(time.Hour)) {
			docheck = true
		}
		if t.Before(rvkResetTime) {
			docheck = true
		}
	}
	if docheck {
		isRevoked, err := r.IsRevoked(e.ctx, iapi.SI())
		if err != nil {
			return false, err
		}
		if !isRevoked {
			err := e.ws.AddRevocationCheck(e.ctx, r.Id(), time.Now().UnixNano())
			if err != nil {
				return false, err
			}
		} else {
			return true, nil
		}
	}
	return false, nil
}

func (e *Engine) IsEntityRevoked(ent *iapi.Entity) (bool, error) {
	for _, r := range ent.Revocations {
		revoked, err := e.revoked(r)
		if err != nil || revoked == true {
			return revoked, err
		}
	}
	return false, nil
}

func (e *Engine) IsNameDeclarationRevoked(nd *iapi.NameDeclaration) (bool, error) {
	for _, r := range nd.Revocations {
		revoked, err := e.revoked(r)
		if err != nil || revoked == true {
			return revoked, err
		}
	}
	return false, nil
}
func (e *Engine) IsAttestationRevoked(att *iapi.Attestation) (bool, error) {
	for _, r := range att.Revocations {
		revoked, err := e.revoked(r)
		if err != nil || revoked == true {
			return revoked, err
		}
	}
	return false, nil
}
