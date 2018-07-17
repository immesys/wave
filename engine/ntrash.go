//+build ignore

package engine

import (
	"context"

	"github.com/immesys/wave/storage"
)

//This function is not allowed to fail
func (e *Engine) handleStorageEvent(change *storage.ChangeEvent) {

	//Not sure what to do about errors here, but they are unlikely
	chkerr := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	if change.IsRevocation {
		chkerr(e.handleRevocation(e.ctx, change.Hash))
	}
	if change.IsDOT {
		e.enqueueEntityResyncIfInteresting(e.ctx, change.DstHash)
	}
}

func (e *Engine) handleRevocation(ctx context.Context, rvkhash []byte) error {
	//Need to work out which entity / dot this is and then
	//call checkDot or checkEntity on that
	//Remember that technically you can have multiple objects with the same
	//revocation hash
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for res := range e.ws.GetInterestingByRevocationHashP(subctx, rvkhash) {
		if res.IsDOT {
			_, err := e.checkPendingDotAndSave(res.Dot)
			if err != nil {
				return err
			}
		} else {
			_, err := e.checkEntityAndSave(res.Entity)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
