package engine

import (
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
)

//Check for revocations
//If decoded, check for expiry and entRevoked
//This must be fairly fast as it gets called frequently on the same stuff
func (e *Engine) checkDotAndSave(d *dot.DOT) (okay bool, err error) {
	srcokay, err := e.checkEntityAndSave(d.SRC)
	if err != nil {
		return false, err
	}
	dstokay, err := e.checkEntityAndSave(d.DST)
	if err != nil {
		return false, err
	}
	expired, err := d.Expired()
	if err != nil {
		return false, err
	}
	revoked, err := e.IsRevoked(e.ctx, d.PlaintextHeader.RevocationHash)
	if err != nil {
		return false, err
	}

	if !srcokay || !dstokay {
		//This dot must move to EntRevoked
		return false, e.ws.MoveDotEntRevokedP(e.ctx, d)
	}
	if revoked {
		return false, e.ws.MoveDotRevokedG(e.ctx, d)
	}
	if expired {
		return false, e.ws.MoveDotExpiredP(e.ctx, d)
	}
	return true, nil
}

func (e *Engine) checkPendingDotAndSave(d *dot.DOT) (okay bool, err error) {
	//Like checkDot but don't check (nonexistant) content
	dstokay, err := e.checkEntityAndSave(d.DST)
	if err != nil {
		return false, err
	}
	revoked, err := e.IsRevoked(e.ctx, d.PlaintextHeader.RevocationHash)
	if err != nil {
		return false, err
	}

	if !dstokay {
		//This dot must move to EntRevoked
		return false, e.ws.MoveDotEntRevokedP(e.ctx, d)
	}
	if revoked {
		return false, e.ws.MoveDotRevokedG(e.ctx, d)
	}
	return true, nil
}

func (e *Engine) checkEntityAndSave(ent *entity.Entity) (bool, error) {
	if ent.Expired() {
		return false, e.ws.MoveEntityExpiredG(e.ctx, ent)
	}
	revoked, err := e.IsRevoked(e.ctx, ent.RevocationHash)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, e.ws.MoveEntityRevokedG(e.ctx, ent)
	}
	return true, nil
}
