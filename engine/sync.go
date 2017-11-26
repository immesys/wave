package engine

import (
	"context"

	"github.com/immesys/wave/entity"
)

//The caller (who is time sensitive) would like to call
//RecursiveSynchronizeEntity on this entity if we are
//interested in it
func (e *Engine) enqueueEntityResyncIfInteresting(ctx context.Context, enthash []byte) error {
	interesting, err := e.ws.IsEntityInterestingP(ctx, enthash)
	if err != nil {
		return err
	}
	if interesting {
		return e.queueEntityForSync(enthash)
	}
	return nil
}

//This function should be quick. Processing should happen elsewhere
func (e *Engine) markEntityInterestingAndQueueForSync(dest []byte) error {
	err := e.ws.MoveEntityInterestingP(e.ctx, dest, 0)
	if err != nil {
		return err
	}
	return e.queueEntityForSync(dest)
}

//This function should be quick. Processing should happen elsewhere
func (e *Engine) queueEntityForSync(dest []byte) error {
	//Like above but skip the mark interesting part
	//(we know we think its interesting already)
	e.resyncQueue <- entity.ArrayHash(dest)
	return nil
}

func (e *Engine) syncLoop() {
	//a bit tricky, when we sync entities, they will add to the queue
	//we also want to deduplicate entries in the queue
	//and we must not block (so there must always be something in
	//the queue)

	//This reads from the queue and inserts into a map of
	//entities to process
	syncup := make(chan bool, 1)
	syncdown := make(chan bool, 1)
	queue := make(map[[32]byte]bool)
	go func() {
		for {
			select {
			case ent := <-e.resyncQueue:
				queue[ent] = true
			case <-syncup:
				//At this point, we know a sync loop has finished.
				//therefore we have either read everything that will
				//be added to the queue already, or it is in the queue's
				//buffer. Once the channel is empty there is no more
				//race

				//Wait until we have at least one entity
				if len(queue) == 0 {
					ent := <-e.resyncQueue
					queue[ent] = true
				}
				//Now wait until the queue is empty
			finalflush:
				for {
					select {
					case ent := <-e.resyncQueue:
						queue[ent] = true
					default:
						break finalflush
					}
				}
				//Now we know the queue is empty, tell the sync
				//loop it owns the map
				syncdown <- true
				//wait for the sync loop to pick its element
				<-syncup
				//now we own the map
			}
		}
	}()

	//The main sync loop
	syncup <- true //tell the reader to wait for us
	<-syncdown     //wait for it to get the message
	for {
		//at the top of the loop, we own the map
		var ent [32]byte
		for ent, _ = range queue {
			break
		}
		delete(queue, ent)
		//We have our element, tell the reader to start
		syncup <- true
		resolvedEnt, err := e.ws.GetEntityByHashG(e.ctx, ent[:])
		if err != nil {
			panic(err)
		}
		err = e.synchronizeEntity(e.ctx, resolvedEnt)
		if err != nil {
			panic(err)
		}
		//Do the sync of the entity
		syncup <- true //tell the reader to stop
		<-syncdown     //wait for the queue to be empty
		//TODO signal the queue is empty
	}
}

// These functions do subsequent state changes
func (e *Engine) synchronizeEntity(ctx context.Context, dest *entity.Entity) (err error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, err = e.moveInterestingDotsToPending(dest)
	if err != nil {
		return err
	}
	err = e.movePendingToLabelledAndActive(dest)
	if err != nil {
		return err
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
		err = e.queueEntityForSync(ent.Hash)
		if err != nil {
			return err
		}
	}
	e.waitForAllSyncToFinish(ctx)
	return nil
}

//When adding dots and whatnot, the sync is asynchronous. This
//will wait until the sync queue is empty and then return
func (e *Engine) waitForAllSyncToFinish(ctx context.Context) {
	panic("ni")
}
