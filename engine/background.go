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
	panic("ni")
}

//The caller (who is time sensitive) would like to call
//RecursiveSynchronizeEntity on this entity if we are
//interested in it
func (e *Engine) enqueueEntityResyncIfInteresting(ctx context.Context, enthash []byte) error {
	panic("ni")
}
