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

		//do not trigger a resync of dst, we are already syncing dst
		err = e.insertPendingDotBlob(dotreg.Data, false)
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
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveDotRevokedG(e.ctx, dot)
}
func (e *Engine) moveEntityToRevoked(ent *entity.Entity) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityRevokedG(e.ctx, ent)
}

//These two functions need to tie in to subscribers of revocations as well
func (e *Engine) moveDotToExpired(dot *dot.DOT) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveDotExpiredP(e.ctx, dot)
}
func (e *Engine) moveEntityToExpired(ctx context.Context, ent *entity.Entity) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityExpiredG(ctx, ent)
}

func (e *Engine) movePendingToLabelledAndActive(dest *entity.Entity) (err error) {
	targetIndex, err := e.ws.GetPartitionLabelKeyIndexP(e.ctx, dest.Hash)
	if err != nil {
		return err
	}
	secretCache := make(map[int]*localdb.Secret)
	subctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	for res := range e.ws.GetPendingDotsP(subctx, dest.Hash, targetIndex) {
		if res.Err != nil {
			return res.Err
		}
		sidx := *res.LabelKeyIndex
		for sidx < targetIndex {
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelKeyP(subctx, dest.Hash, sidx)
				if serr != nil {
					return serr
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
			return err
		}
		if decodeResult.BadOrMalformed {
			if err := e.ws.MoveDotMalformedP(e.ctx, decodeResult.Hash); err != nil {
				return err
			}
		} else if decodeResult.FullyDecrypted || decodeResult.PartitionDecrypted {
			//move this out of pending and into labelled. I know it seems weird to
			//put it in labelled when it may be fully decrypted, but that way there
			//is one code path to active and it simplifies reacting to new active dots
			//which trigger upstream resync
			//We also actually don't even try to fully decrypt it, so not much
			//cpu time is lost

			//This state transition is interesting. We must test if this
			//dot transitions into labelled or active, and we must do so
			//while holding the mutex on the dst hash to ensure no new
			//keys that could potentially decode the dot race with this test
			e.partitionMutex.Lock()
			fullDecodeResult, err := dot.DecryptContent(e.ctx, decodeResult.DOT, dctx)

			if err != nil {
				e.partitionMutex.Unlock()
				return err
			}
			if fullDecodeResult.FullyDecrypted {
				//Lock no longer needed, because its not going into the labelled queue
				e.partitionMutex.Unlock()
				//This must go into active
				if err := e.insertActiveDot(fullDecodeResult.DOT); err != nil {
					return err
				}
			} else {
				//This dot is labelled. When new secrets appear, they will be tested
				//against it
				err := e.ws.MoveDotLabelledP(e.ctx, decodeResult.DOT)
				e.partitionMutex.Unlock()
				if err != nil {
					return err
				}
			}
		} else {
			//We failed to decrypt even the label.
			//We need to update the label key index and try again when we get new label keys
			if err := e.ws.UpdateDotPendingP(e.ctx, decodeResult.DOT, targetIndex); err != nil {
				return err
			}
		}
	}
	return nil
}

//Returns a map of source entities to the number of dots they have granted
// func (e *Engine) moveLabelledToActiveAndInsertKey(dest *entity.Entity, key *localdb.Secret) (err error) {
// 	//Before we insert the key, we need to ensure we process all labelled dots
// 	//that it might match (under mutex)
// 	if !key.IsContentKey {
// 		panic("huh?")
// 	}
// 	arrHash := dest.ArrayHash()
// 	if e.partitionMutex[arrHash] == nil {
// 		e.partitionMutex[arrHash] = new(sync.Mutex)
// 	}
// 	e.partitionMutex[arrHash].Lock()
// 	defer e.partitionMutex[arrHash].Unlock()
// 	ctx, cancel := context.WithCancel(e.ctx)
// 	defer cancel()
// 	for dt := range e.ws.GetLabelledDotsP(ctx, dest.Hash, key.Slots) {
// 		//TODO decrypt and process
// 		//No need to pass list of label keys to use, label is already
// 		//decrypted
// 		dctx := NewEngineDecryptionContext(e, nil)
// 		fullDecodeResult, err := dot.DecryptContent(e.ctx, dt.Dot, dctx)
// 		if err != nil {
// 			return err
// 		}
// 		if fullDecodeResult.FullyDecrypted {
// 			if err := e.insertActiveDot(fullDecodeResult.DOT); err != nil {
// 				return err
// 			}
// 		} else {
// 			panic("we expected the dot to decrypt with the given key")
// 		}
// 	}
// 	//Okay all dots have been processed, no new ones have been inserted
// 	//because we hold the mutex. Insert the new key and release the mutex
// 	return e.ws.InsertOAQUEKeysForP(ctx, dest.Hash, key.Slots, key.Key)
// }

//This function inserts an OQAUE content key and returns the labelled dots
//that were decrypted by it that were granted to ENT
//the key obviously comes FROM ENT (so the SRC of a dot)
func (e *Engine) insertKeyAndUnlockLabelled(ent *entity.Entity, key *localdb.Secret) (map[[32]byte]*dot.DOT, error) {
	//the rule is: this key must be compared agaisnt all labelled dots and inserted
	//in the database before any further labelled dots can be inserted (no racing)
	//i.e lock, compare labelled, collate list of new active,
	//move old labelled to active, insert key, unlock, return new active for key processing
	//we don't insert the new actives because they too contain keys so must be handled carefully
	//Before we insert the key, we need to ensure we process all labelled dots
	//that it might match (under mutex)
	if !key.IsContentKey {
		panic("huh?")
	}
	rv := make(map[[32]byte]*dot.DOT)
	e.partitionMutex.Lock()
	defer e.partitionMutex.Unlock()
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	for dt := range e.ws.GetLabelledDotsP(ctx, ent.Hash, key.Slots) {
		//TODO decrypt and process
		//No need to pass list of label keys to use, label is already
		//decrypted
		dctx := NewEngineDecryptionContext(e, nil)
		fullDecodeResult, err := dot.DecryptContent(e.ctx, dt.Dot, dctx)
		if err != nil {
			return nil, err
		}
		if fullDecodeResult.FullyDecrypted {
			//add it to the RV
			rv[fullDecodeResult.DOT.ArrayHash()] = fullDecodeResult.DOT
			err := e.moveDotToActiveWithoutProcessingKeys(fullDecodeResult.DOT)
			if err != nil {
				return nil, err
			}
		} else {
			panic("we expected the dot to decrypt with the given key")
		}
	}
	//Okay all labelled dots have been processed, no new ones have been inserted
	//because we hold the mutex. Insert the new key and release the mutex
	err := e.ws.InsertOAQUEKeysForP(ctx, ent.Hash, key.Slots, key.Key)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

//As we move dots to labelled, we get keys. This tries to be a little efficient
//in not trying the exact same key more than once
func (e *Engine) recursiveInsertKeyAndMoveLabelled(ent *entity.Entity, newkey *localdb.Secret) error {
	keysToProcess := make(map[[32]byte]*localdb.Secret)
	keysToProcess[newkey.Hash()] = newkey
	for len(keysToProcess) > 0 {
		for h, key := range keysToProcess {
			delete(keysToProcess, h)
			newDots, err := e.insertKeyAndUnlockLabelled(ent, key)
			if err != nil {
				return err
			}
			for _, d := range newDots {
				secret := &localdb.Secret{
					IsContentKey: true,
					Slots:        d.Inheritance.DelegationPartition,
					Key:          d.Inheritance.DelegationKey,
				}
				keysToProcess[secret.Hash()] = secret
			}
		}
	}
	return nil
}
func (e *Engine) moveDotToActiveWithoutProcessingKeys(d *dot.DOT) error {
	return e.ws.MoveDotActiveP(e.ctx, d)
}

//This particular code path also moves dots from labelled to active
//that are decoded as a result of this dot being added to the system
//it should not be called while the partition mutex for the SRC
//of the dot is held
func (e *Engine) insertActiveDot(d *dot.DOT) error {
	okay, err := e.checkDotAndSave(d)
	if err != nil {
		return err
	}
	if !okay {
		//checkdot will handle the repercussions, we can just return
		return nil
	}

	//Process the label keys
	_, err = e.ws.InsertPartitionLabelKeyP(e.ctx, d.SRC.Hash, d.Content.NS, d.Inheritance.PartitionLabelKey)
	if err != nil {
		return err
	}

	//Process the content keys
	secret := localdb.Secret{
		IsContentKey: true,
		Slots:        d.Inheritance.DelegationPartition,
		Key:          d.Inheritance.DelegationKey,
	}
	err = e.recursiveInsertKeyAndMoveLabelled(d.SRC, &secret)
	if err != nil {
		return err
	}
	err = e.ws.MoveDotActiveP(e.ctx, d)
	if err != nil {
		return err
	}

	//This must also queue for resync the granting entity. This will take care of the
	//new dots that can move from pending to labelled (and we just took care of
	//the ones alreay in labelled that moved to active)
	return e.markEntityInterestingAndQueueForSync(d.SRC.Hash)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop
func (e *Engine) insertPendingDot(d *dot.DOT) error {
	//We can't check entities, but we can ensure its not revoked
	okay, err := e.checkPendingDotAndSave(d)
	if err != nil {
		return err
	}
	if !okay {
		//checkPendingDot will handle repercussions, just
		//stop here
		return nil
	}
	//Dot is not revoked, put it in pending
	//We did not try any secrets on this dot yet, so SI = 0
	return e.ws.MoveDotPendingP(e.ctx, d, 0)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop. if resyncDestination is called,
//the dst will be asynchronously brought up to date
//to ensure this new dot is decrypted if possible
func (e *Engine) insertPendingDotBlob(d []byte, resyncDestination bool) error {
	dres, err := dot.UnpackDOT(e.ctx, d)
	if err != nil {
		return err
	}
	if dres.BadOrMalformed {
		return e.ws.MoveDotMalformedP(e.ctx, dres.Hash)
	}
	err = e.insertPendingDot(dres.DOT)
	if err != nil {
		return err
	}
	if resyncDestination {
		return e.enqueueEntityResyncIfInteresting(e.ctx, dres.DOT.PlaintextHeader.DST)
	}
	return nil
}
