package engine

import (
	"context"
	"fmt"

	"github.com/immesys/wave/iapi"
)

func sliceToArray(b []byte) (rv [32]byte) {
	copy(rv[:], b[:])
	return
}

//The caller (who is time sensitive) would like to call
//RecursiveSynchronizeEntity on this entity if we are
//interested in it
func (e *Engine) enqueueEntityResyncIfInteresting(ctx context.Context, enthash iapi.HashSchemeInstance) error {
	interesting, err := e.ws.IsEntityInterestingP(ctx, enthash)
	if err != nil {
		return err
	}
	if interesting {
		return e.queueEntityForSync(enthash.Value())
	}
	return nil
}

//This function should be quick. Processing should happen elsewhere
func (e *Engine) MarkEntityInterestingAndQueueForSync(dest *iapi.Entity, loc iapi.LocationSchemeInstance) error {
	err := e.ws.MoveEntityInterestingP(e.ctx, dest, loc)
	if err != nil {
		return err
	}
	return e.queueEntityForSync(dest.Keccak256())
}

//This function should be quick. Processing should happen elsewhere
func (e *Engine) queueEntityForSync(dest []byte) error {
	//Like above but skip the mark interesting part
	//(we know we think its interesting already)
	e.totalMutex.Lock()
	if e.totalSyncRequests == e.totalCompletedSyncs {
		//We are about to be unequal, replace the channel
		e.totalEqual = make(chan struct{})
	}
	e.totalSyncRequests++
	e.totalMutex.Unlock()
	e.resyncQueue <- sliceToArray(dest)
	return nil
}

func (e *Engine) syncLoop() {
	//a bit tricky, when we sync entities, they will add to the queue
	//we also want to deduplicate entries in the queue
	//and we must not block (so there must always be something in
	//the queue)

	//This reads from the queue and inserts into a map of
	//entities to process
	//fmt.Printf("starting sync loop\n")
	syncup := make(chan bool, 1)
	syncdown := make(chan bool, 1)
	queue := make(map[[32]byte]bool)
	go func() {
		for {
			select {
			case ent := <-e.resyncQueue:
				if queue[ent] {
					//This entity is already queued, so we can
					//consider this request as handled but because
					//we know there is something in the map we know
					//the two counts can't be equal
					e.totalMutex.Lock()
					e.totalCompletedSyncs++
					e.totalMutex.Unlock()
				} else {
					queue[ent] = true
				}
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
						if queue[ent] {
							//This entity is already queued, so we can
							//consider this request as handled but because
							//we know there is something in the map we know
							//the two counts can't be equal
							e.totalMutex.Lock()
							e.totalCompletedSyncs++
							e.totalMutex.Unlock()
						} else {
							queue[ent] = true
						}
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
		ok := false
		for ent, _ = range queue {
			ok = true
			break
		}
		if !ok {
			panic("we expected at least one element?")
		}
		delete(queue, ent)
		//We have our element, tell the reader to start
		syncup <- true
		resolvedEnt, err := e.ws.GetEntityByHashSchemeInstanceG(e.ctx, &iapi.HashSchemeInstance_Keccak_256{Val: ent[:]})
		if err != nil {
			panic(err)
		}
		if resolvedEnt == nil {
			panic("synchronize nil entity?")
		}
		fmt.Printf(">syncE\n")
		err = e.synchronizeEntity(e.ctx, resolvedEnt)
		if err != nil {
			panic(err)
		}
		fmt.Printf("<syncE\n")
		e.totalMutex.Lock()
		e.totalCompletedSyncs++
		if e.totalCompletedSyncs > e.totalSyncRequests {
			panic(fmt.Sprintf("%d > %d", e.totalCompletedSyncs, e.totalSyncRequests))
		}
		if e.totalCompletedSyncs == e.totalSyncRequests {
			//they are equal, close the channel to notify ppl if it hasn't already been closed
			select {
			case <-e.totalEqual:
			default:
				close(e.totalEqual)
			}
		}
		e.totalMutex.Unlock()
		//atomic.AddInt64(&e.totalCompletedSyncs, 1)
		//Do the sync of the entity
		syncup <- true //tell the reader to stop
		<-syncdown     //wait for the queue to be empty
	}
}

// These functions do subsequent state changes
func (e *Engine) synchronizeEntity(ctx context.Context, dest *iapi.Entity) (err error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	fmt.Printf(">moveInterestingAttToPending\n")
	_, err = e.moveInterestingObjectsToPending(dest)
	if err != nil {
		fmt.Printf("se Err 1\n")
		return err
	}
	fmt.Printf("<moveInterestingAttToPending\n")
	fmt.Printf(">movePendingToLabelled\n")
	err = e.movePendingToLabelledAndActive(dest)
	if err != nil {
		//fmt.Printf("se Err 2\n")
		return err
	}
	fmt.Printf("<movePendingToLabelled\n")
	return nil
}

//This will bring up to date all entities marked as interesting in the
//database (a persistent list) this happens infrequently (generally on startup)
func (e *Engine) updateAllInterestingEntities(ctx context.Context) error {
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	//We artificially put a fake request in here so that the done channel
	//will not be closed until we are done enqueueing all interesting entities
	fmt.Printf(">updateAllInteresting\n")
	e.totalMutex.Lock()
	if e.totalSyncRequests == e.totalCompletedSyncs {
		//We are about to be unequal, replace the channel
		e.totalEqual = make(chan struct{})
	}
	e.totalSyncRequests++
	e.totalMutex.Unlock()
	for res := range e.ws.GetInterestingEntitiesP(subctx) {
		if res.Err != nil {
			return res.Err
		}
		// ent, err := e.ws.GetEntityByHashG(subctx, res.Hash)
		// if err != nil {
		// 	return err
		// }
		err := e.queueEntityForSync(res.Entity.Keccak256())
		if err != nil {
			return err
		}
	}
	//The perspective is also interesting
	err := e.queueEntityForSync(e.perspective.Entity.Keccak256())
	if err != nil {
		return err
	}
	//fmt.Printf("finished interesting entity\n")
	//Now we have to remove our fake request, but we may actually have to
	//handle them being equal now too
	e.totalMutex.Lock()
	e.totalSyncRequests--
	if e.totalCompletedSyncs > e.totalSyncRequests {
		panic("completed > requested")
	}
	if e.totalCompletedSyncs == e.totalSyncRequests {
		//they are equal, close the channel to notify ppl
		close(e.totalEqual)
	}
	fmt.Printf("<updateAllInteresting\n")
	e.totalMutex.Unlock()
	return nil
}
