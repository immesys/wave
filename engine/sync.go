package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/wave/entity"
)

// These functions do subsequent state changes
func (e *Engine) synchronizeEntity(ctx context.Context, dest *entity.Entity) (sources map[*entity.Entity]int, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_, err = e.moveInterestingDotsToPending(dest)
	if err != nil {
		return nil, err
	}
	_, err = e.movePendingToLabelled(dest)
	if err != nil {
		return nil, err
	}
	return e.moveLabelledToActive(dest)
}

func (e *Engine) RecursiveSynchronizeEntity(ctx context.Context, dest *entity.Entity) (err error) {
	then := time.Now()
	toprocess, err := e.synchronizeEntity(ctx, dest)
	//For all sources, synchronize them too
	for len(toprocess) > 0 {
		for src, _ := range toprocess {
			additional, err := e.synchronizeEntity(ctx, src)
			if err != nil {
				return err
			}
			for k, v := range additional {
				toprocess[k] += v
			}
			delete(toprocess, src)
		}
	}
	now := time.Now()
	delta := now.Sub(then)
	if delta > 1*time.Millisecond {
		fmt.Printf("RecursiveSync: %s\n", delta)
	}
	return nil
}

//This will bring up to date all entities marked as interesting in the
//database (a persistent list) this happens infrequently (generally on startup)
func (e *Engine) updateAllInterestingEntities(ctx context.Context) error {
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for res := range e.ws.GetInterestingEntitiesP(subctx) {
		if res.Err != nil {
			return res.Err
		}
		ent, err := e.ws.GetEntityByHashG(subctx, res.Hash)
		if err != nil {
			return err
		}
		err = e.RecursiveSynchronizeEntity(ctx, ent)
		if err != nil {
			return err
		}
	}
	return nil
}
