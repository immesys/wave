package engine

import (
	"context"

	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
	localdb "github.com/immesys/wave/localdb/types"
)

// Raw state change functions
// NONE OF THESE WILL EXECUTE SUBSEQUENT STATE CHANGES
// You must do that at a higher level
// These must all be super efficient (basically noop if there are no changes)

//These functions return the number of changes to facilitate efficient looping
func (e *Engine) moveInterestingDotsToPending(dest *entity.Entity) (changed int, err error) {
	// Update the dots
	index, err := e.ws.GetEntityDotIndexP(e.ctx, dest.Hash)
	if err != nil {
		return 0, err
	}
	indexChanged := false
	numChanged := 0
	for {
		dotreg, _, err := e.st.RetrieveDOTByEntityIndex(e.ctx, dest.Hash, index)
		if dotreg == nil {
			//index already points to next (waiting)
			break
		}

		err = e.insertPendingDotBlob(dotreg.Data)
		if err != nil {
			return 0, err
		}

		index++
		numChanged++
		indexChanged = true
		if index == dotreg.MaxIndex {
			break
		}
	}
	if indexChanged {
		return numChanged, e.ws.SetEntityDotIndexP(e.ctx, dest.Hash, index)
	}
	return 0, nil
}

//These two functions need to tie in to subscribers of revocations as well
func (e *Engine) moveDotToRevoked(dot *dot.DOT) error {
	panic("ni") //TODO notify subscribers
	return e.ws.MoveDotRevokedG(e.ctx, dot)
}
func (e *Engine) moveEntityToRevoked(ent *entity.Entity) error {
	panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityRevokedG(e.ctx, ent)
}

//These two functions need to tie in to subscribers of revocations as well
func (e *Engine) moveDotToExpired(dot *dot.DOT) error {
	panic("ni") //TODO notify subscribers
	return e.ws.MoveDotExpiredP(e.ctx, dot)
}
func (e *Engine) moveEntityToExpired(ctx context.Context, ent *entity.Entity) error {
	panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityExpiredG(ctx, ent)
}

func (e *Engine) movePendingToLabelled(dest *entity.Entity) (changed int, err error) {
	targetIndex, err := e.ws.GetPartitionLabelSecretIndexP(e.ctx, dest.Hash)
	if err != nil {
		return 0, err
	}
	secretCache := make(map[int]*localdb.Secret)
	subctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	moved := 0
	for res := range e.ws.GetPendingDotsP(subctx, dest.Hash, targetIndex) {
		if res.Err != nil {
			return 0, res.Err
		}
		sidx := *res.SecretIndex
		for sidx < targetIndex {
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelSecretP(subctx, dest.Hash, sidx)
				if serr != nil {
					return 0, serr
				}
				if secret == nil {
					panic("Unexpected nil secret")
				}
				secretCache[sidx] = secret
			}
		}
		dctx := NewEngineDecryptionContext(e, secretCache)
		decodeResult, err := dot.DecryptLabel(e.ctx, res.Dot, dctx)
		if err != nil {
			return 0, err
		}
		if decodeResult.BadOrMalformed {
			if err := e.ws.MoveDotMalformedP(e.ctx, decodeResult.Hash); err != nil {
				return 0, err
			}
		} else if decodeResult.FullyDecrypted || decodeResult.PartitionDecrypted {
			//move this out of pending and into labelled. I know it seems weird to
			//put it in labelled when it may be fully decrypted, but that way there
			//is one code path to active and it simplifies reacting to new active dots
			//which trigger upstream resync
			//We also actually don't even try to fully decrypt it, so not much
			//cpu time is lost
			moved++
			if err := e.ws.MoveDotLabelledP(e.ctx, decodeResult.DOT); err != nil {
				return 0, err
			}
		} else {
			//We failed to decrypt it
			//We need to update the secret index
			if err := e.ws.UpdateDotPendingP(e.ctx, decodeResult.DOT, targetIndex); err != nil {
				return 0, err
			}
		}
	}
	return moved, nil
}

//Returns a map of source entities to the number of dots they have granted
func (e *Engine) moveLabelledToActive(dest *entity.Entity) (sources map[*entity.Entity]int, err error) {
	//TODO we need an efficient mechanism for moving labelled dots to active
	//TODO we need a secret log a bit like the partition labels I think
	//this function must not be proportional to the number of labelled dots, just
	//the number of new (distinct) partition secrets
	panic("ni")
	//this should probably call checkDOT on the dot
	//it must also call checkEntity on the dest
}

//Learned OOB or something
func (e *Engine) insertPendingDot(d *dot.DOT) error {
	//We can't check entities, but we can ensure its not revoked
	isrvk, err := e.IsRevoked(e.ctx, d.PlaintextHeader.RevocationHash)
	if err != nil {
		return err
	}
	if isrvk {
		return e.ws.MoveDotRevokedG(e.ctx, d)
	}
	//Dot is not revoked, put it in pending
	//We did not try any secrets on this dot yet, so SI = 0
	return e.ws.MoveDotPendingP(e.ctx, d, 0)
}

//Learned OOB or something
func (e *Engine) insertPendingDotBlob(d []byte) error {
	dres, err := dot.UnpackDOT(e.ctx, d)
	if err != nil {
		return err
	}
	if dres.BadOrMalformed {
		return e.ws.MoveDotMalformedP(e.ctx, dres.Hash)
	}
	return e.insertPendingDot(dres.DOT)
}
