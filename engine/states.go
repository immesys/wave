package engine

import (
	"context"

	"github.com/immesys/wave/iapi"
)

// Raw state change functions
// NONE OF THESE WILL EXECUTE SUBSEQUENT STATE CHANGES
// You must do that at a higher level
// These must all be super efficient (basically noop if there are no changes)

//These functions return the number of changes to facilitate efficient looping
func (e *Engine) moveInterestingAttestationsToPending(dest *iapi.Entity) (changed int, err error) {

	//If we return early due to error, ensure the functions we call returning channels
	//clean up cleanly
	sctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	changes := 0
nextlocation:
	for loc := range e.ws.LocationsForEntity(sctx, dest) {
		if loc.Err != nil {
			return 0, err
		}
		hashscheme, err := e.st.HashSchemeFor(loc.Location)
		if err != nil {
			panic(err)
		}
		for {
			// get current token
			okay, token, err := e.ws.GetEntityQueueTokenP(sctx, loc.Location, dest.Keccak256HI())
			if err != nil {
				return 0, err
			}
			if !okay {
				panic("interestingToPending unknown entity")
			}
			// get queue entry for that token
			der, err := dest.DER()
			if err != nil {
				panic(err)
			}
			hi := hashscheme.Instance(der)
			object, nextToken, err := e.st.IterateQeueue(e.ctx, loc.Location, hi, token)
			if err != nil {
				return 0, err
			}
			if object == nil {
				//There is nothing more in this queue on this location yet
				continue nextlocation
			}
			//The object is probably an attestation
			attestation, err := e.st.GetAttestation(e.ctx, loc.Location, object)
			if err != nil {
				return 0, err
			}
			if attestation == nil {
				//object was not an attestation, that is fine
			} else {
				//do not trigger a resync of dst, we are already syncing dst
				err = e.insertPendingAttestation(attestation, false)
				if err != nil {
					return 0, err
				}
				changes++
			}
			err := e.ws.SetEntityQueueTokenP(sctx, loc.Location, dest.Keccak256HI(), nextToken)
			if err != nil {
				panic(err)
			}
		}
	}

	return changes, nil
}

//These two functions need to tie in to subscribers of revocations as well
func (e *Engine) moveAttestationToRevoked(att *iapi.Attestation) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveAttestationRevokedG(e.ctx, att)
}
func (e *Engine) moveEntityToRevoked(ent *iapi.Entity) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityRevokedG(e.ctx, ent)
}

//These two functions need to tie in to subscribers of revocations as well
func (e *Engine) moveAttestationToExpired(att *iapi.Attestation) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveAttestationExpiredP(e.ctx, att)
}
func (e *Engine) moveEntityToExpired(ctx context.Context, ent *iapi.Entity) error {
	//panic("ni") //TODO notify subscribers
	return e.ws.MoveEntityExpiredG(ctx, ent)
}

func (e *Engine) movePendingToLabelledAndActive(dest *iapi.Entity) (err error) {
	okay, targetIndex, err := e.ws.GetEntityPartitionLabelKeyIndexP(e.ctx, dest.Hash)
	if err != nil {
		return err
	}
	if !okay {
		panic("LKI on unknown entity?")
	}
	secretCache := make(map[int]iapi.EntitySecretKeySchemeInstance)
	subctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	for res := range e.ws.GetPendingAttestationsP(subctx, dest.Keccak256HI(), targetIndex) {
		if res.Err != nil {
			return res.Err
		}
		sidx := *res.LabelKeyIndex
		for sidx < targetIndex {
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelKeyP(subctx, dest.Keccak256HI(), sidx)
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
		e.partitionMutex.Lock()
		defer e.partitionMutex.Unlock()
		//When we parse the attestation here, it is for a given set of
		//partition keys available in the engine. The keys can't change because
		//we hold the mutex
		rpa, err := iapi.ParseAttestation(subctx, &iapi.PParseAttestation{
			Attestation:       res.Attestation,
			DecryptionContext: dctx,
		})
		if err != nil {
			panic(err)
		}

		//The dot will either
		// stay pending
		// move to labelled
		// move to active
		//if it is moving to labelled it must happen while we still hold the
		//partitionmutex
		if rpa.IsMalformed {
			if err := e.ws.MoveAttestationMalformedP(e.ctx, res.Attestation.Keccak256HI()); err != nil {
				return err
			}
		}

		if rpa.Attestation.DecryptedBody != nil {
			//DOT is transitioning to active
			if err := e.insertActiveDot(fullDecodeResult.DOT); err != nil {
				return err
			}
			continue
		}
		if ex, ok := rpa.ExtraInfo.(iapi.WR1PartitionExtra); ok {
			//This is a WR1 dot that has been labelled, transition to labelled
			if err := e.ws.MoveAttestationLabelledP(subctx, rpa.Attestation); err != nil {
				return err
			}
			continue
		}
		//This attestation failed to decrypt at all
		//update the secret key index
		if err := e.ws.UpdateAttestationPendingP(e.ctx, rpa.Attestation, targetIndex); err != nil {
			return err
		}
		continue
	} //next pending attestation
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
func (e *Engine) insertKeyAndUnlockLabelled(ent *iapi.Entity, key iapi.SlottedSecretKey) (map[[32]byte]*iapi.Attestation, error) {
	//the rule is: this key must be compared agaisnt all labelled dots and inserted
	//in the database before any further labelled dots can be inserted (no racing)
	//i.e lock, compare labelled, collate list of new active,
	//move old labelled to active, insert key, unlock, return new active for key processing
	//we don't insert the new actives because they too contain keys so must be handled carefully
	//Before we insert the key, we need to ensure we process all labelled dots
	//that it might match (under mutex)

	rv := make(map[[32]byte]*iapi.Attestation)
	e.partitionMutex.Lock()
	defer e.partitionMutex.Unlock()
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	dctx := NewEngineDecryptionContext(e, nil)
	for dt := range e.ws.GetLabelledAttestationsP(ctx, ent.Keccak256HI(), key.Slots()) {
		//No need to pass list of label keys to use, label is already
		//decrypted
		rpa, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
			Attestation:       dt.Attestation,
			DecryptionContext: dctx,
		})
		if err != nil {
			panic(err)
		}
		if rpa.IsMalformed {
			e.ws.MoveAttestationMalformedP(ctx, dt.Attestation.Keccak256HI())
			continue
		}
		if rpa.Attestation.DecryptedBody != nil {
			rv[rpa.Attestation.ArrayKeccak256()] = rpa.Attestation
			err := e.moveAttestationToActiveWithoutProcessingKeys(rpa.Attestation)
			if err != nil {
				return nil, err
			}
		} else {
			panic("we expected the dot to decrypt with the given key")
		}
	}
	//Okay all labelled dots have been processed, no new ones have been inserted
	//because we hold the mutex. Insert the new key and release the mutex
	err := e.ws.InsertWR1KeysForP(ctx, ent.Keccak256HI(), key)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

//As we move dots from labelled, we get keys. This tries to be a little efficient
//in not trying the exact same key more than once
func (e *Engine) recursiveInsertKeyAndMoveLabelled(ent *iapi.Entity, newkey iapi.SlottedSecretKey) error {
	keysToProcess := make(map[[32]byte]iapi.SlottedSecretKey)
	keysToProcess[newkey.IdHash()] = newkey
	for len(keysToProcess) > 0 {
		for h, key := range keysToProcess {
			delete(keysToProcess, h)
			newDots, err := e.insertKeyAndUnlockLabelled(ent, key)
			if err != nil {
				return err
			}
			for _, d := range newDots {
				kz, err := d.WR1SecretKeys()
				if err != nil {
					panic(err)
				}
				for _, k := range kz {
					keysToProcess[k.IdHash] = k
				}
			}
		}
	}
	return nil
}
func (e *Engine) moveAttestationToActiveWithoutProcessingKeys(d *iapi.Attestation) error {
	return e.ws.MoveAttestationActiveP(e.ctx, d)
}

//This particular code path also moves dots from labelled to active
//that are decoded as a result of this dot being added to the system
//it should not be called while the partition mutex for the SRC
//of the dot is held
func (e *Engine) insertActiveAttestation(d *iapi.Attestation) error {
	okay, err := e.checkAttestationAndSave(d)
	if err != nil {
		return err
	}
	if !okay {
		//checkdot will handle the repercussions, we can just return
		return nil
	}
	attester, _, err := d.Attester()
	if err != nil {
		return err
	}
	//Process the label keys
	for _, k := range d.WR1DomainVisibilityKeys() {

		_, err := e.ws.InsertPartitionLabelKeyP(e.ctx, attester, k)
	}

	for _, k := range d.WR1SlottedKeys() {
		err := e.recursiveInsertKeyAndMoveLabelled(attester, k)
		if err != nil {
			return err
		}
	}

	err = e.ws.MoveAttestationActiveP(e.ctx, d)
	if err != nil {
		return err
	}

	//This must also queue for resync the granting entity. This will take care of the
	//new dots that can move from pending to labelled (and we just took care of
	//the ones alreay in labelled that moved to active)
	return e.markEntityInterestingAndQueueForSync(attester)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop
func (e *Engine) insertPendingAttestation(d *iapi.Attestation) error {
	//We can't check entities, but we can ensure its not revoked
	okay, err := e.checkPendingAttestationAndSave(d)
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
	return e.ws.MoveAttestationPendingP(e.ctx, d, 0)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop. if resyncDestination is called,
//the dst will be asynchronously brought up to date
//to ensure this new dot is decrypted if possible
func (e *Engine) insertPendingAttestationSync(d *iapi.Attestation, resyncDestination bool) error {
	err = e.insertPendingDot(d)
	if err != nil {
		return err
	}
	if resyncDestination {
		dst, _ := d.Subject()
		return e.enqueueEntityResyncIfInteresting(e.ctx, dst)
	}
	return nil
}
