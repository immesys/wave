package engine

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strconv"

	"github.com/immesys/wave/iapi"
)

func getGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// Raw state change functions
// NONE OF THESE WILL EXECUTE SUBSEQUENT STATE CHANGES
// You must do that at a higher level
// These must all be super efficient (basically noop if there are no changes)

//These functions return the number of changes to facilitate efficient looping
func (e *Engine) moveInterestingObjectsToPending(dest *iapi.Entity) (changed int, err error) {

	//If we return early due to error, ensure the functions we call returning channels
	//clean up cleanly
	sctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	//fmt.Printf("XX MOVE INTERESTING [[%q]]\n", sctx.Value(consts.PerspectiveKey).(*iapi.EntitySecrets).Entity.Keccak256HI().MultihashString())
	// bf := make([]byte, 8000)
	// count := runtime.Stack(bf, false)
	// bf = bf[:count]
	// fmt.Printf("stack: %s\n", string(bf))
	changes := 0
	locs, err := e.ws.LocationsForEntity(sctx, dest)
	if err != nil {
		return 0, err
	}
nextlocation:
	for _, loc := range locs {
		hashscheme, err := e.st.HashSchemeFor(loc)
		if err != nil {
			panic(err)
		}
		for {
			// get current token
			okay, token, err := e.ws.GetEntityQueueTokenP(sctx, loc, dest.Keccak256HI())
			if err != nil {
				return 0, err
			}
			//fmt.Printf("got token %q for entity %s, %v\n", token, dest.Keccak256HI().MultihashString(), getGID())
			if !okay {
				panic("interestingToPending unknown entity")
			}
			// get queue entry for that token
			der, err := dest.DER()
			if err != nil {
				panic(err)
			}
			hi := hashscheme.Instance(der)
			object, nextToken, err := e.st.IterateQeueue(e.ctx, loc, hi, token)
			if err != nil && err != iapi.ErrNoMore {
				return 0, err
			}
			if object == nil || err == iapi.ErrNoMore {
				//There is nothing more in this queue on this location yet
				continue nextlocation
			}

			//Check if this object is a known attestation or namedecl
			foundAtt, _, err := e.ws.GetAttestationP(e.ctx, object)
			if err != nil {
				return 0, err
			}
			skip := false
			if foundAtt != nil {
				skip = true
			}
			if !skip {
				foundNameDecl, err := e.ws.GetNameDeclarationP(e.ctx, object)
				if err != nil {
					return 0, err
				}
				if foundNameDecl != nil {
					skip = true
				}
			}

			if !skip {
				//The object is probably an attestation or name declaration
				storageResult, err := e.st.GetAttestationOrDeclaration(e.ctx, loc, object)
				if err != nil {
					return 0, err
				}

				if storageResult != nil {
					if storageResult.Attestation != nil {
						err = e.insertPendingAttestationSync(storageResult.Attestation, false)
						if err != nil {
							return 0, err
						}
						changes++
					}
					if storageResult.NameDeclaration != nil {
						//fmt.Printf("XX got SR ND\n")
						//TODO reparse name declaration to validate signature (needs attester resolution)
						nd, err := e.reparseND(storageResult.NameDeclaration)
						if err != nil {
							return 0, err
						}
						if nd == nil {
							//malformed
							goto settoken
						}
						if nd.Decoded() {
							//fmt.Printf("ND was decoded\n")
							//This was a plaintext ND, skip the pipeline
							err := e.insertActiveNameDeclaration(e.ctx, nd)
							if err != nil {
								return 0, err
							}
						} else {
							//fmt.Printf("ND was not decoded\n")
							err = e.insertPendingNameDeclaration(storageResult.NameDeclaration)
							if err != nil {
								return 0, err
							}
						}
						changes++
					}
				}
			}
		settoken:
			//fmt.Printf("setting entity queue token to %q in ws %s\n", nextToken, dest.Keccak256HI().MultihashString())
			err = e.ws.SetEntityQueueTokenP(sctx, loc, dest.Keccak256HI(), nextToken)
			if err != nil {
				panic(err)
			}
		}
	}

	return changes, nil
}

func (e *Engine) reparseND(nd *iapi.NameDeclaration) (*iapi.NameDeclaration, error) {
	dctx := NewEngineDecryptionContext(e)
	rv, err := iapi.ParseNameDeclaration(e.ctx, &iapi.PParseNameDeclaration{
		NameDeclaration: nd,
		Dctx:            dctx,
	})
	if err != nil {
		return nil, err
	}
	if rv.IsMalformed {
		return nil, nil
	}
	return rv.Result, nil
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

type attOrND struct {
	A             *iapi.Attestation
	N             *iapi.NameDeclaration
	LabelKeyIndex *int
	Err           error
}

func (e *Engine) movePendingToLabelledAndActive(dest *iapi.Entity) (err error) {
	fmt.Printf("MPLA 0\n")
	var targetIndex int
	isdirect := bytes.Equal(dest.Keccak256(), e.perspective.Entity.Keccak256())
	okay, targetIndex, err := e.ws.GetEntityPartitionLabelKeyIndexP(e.ctx, dest.Keccak256HI())
	if err != nil {
		return err
	}
	if !okay {
		panic("LKI on unknown entity?")
	}

	secretCache := make(map[int]iapi.EntitySecretKeySchemeInstance)
	subctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	//fmt.Printf("targetindex: %v\n", targetIndex)
	fmt.Printf("MPLA 1\n")
	//fmt.Printf("subj MPLA: %x\n", dest.Keccak256HI())
	getTargetIndex := targetIndex
	if isdirect {
		getTargetIndex = -1
	}

	todo := make(chan attOrND, 10)
	go func() {
		for res := range e.ws.GetPendingAttestationsP(subctx, dest.Keccak256HI(), getTargetIndex) {
			if res.Err != nil {
				todo <- attOrND{
					Err: res.Err,
				}
			}
			todo <- attOrND{
				A:             res.Attestation,
				LabelKeyIndex: res.LabelKeyIndex,
			}
		}
		for res := range e.ws.GetPendingNameDeclarationP(subctx, dest.Keccak256HI(), getTargetIndex) {
			if res.Err != nil {
				todo <- attOrND{
					Err: res.Err,
				}
			}
			todo <- attOrND{
				N:             res.NameDeclaration,
				LabelKeyIndex: res.LabelKeyIndex,
			}
		}
		close(todo)
	}()

	for res := range todo {
		//fmt.Printf("MPLA 2\n")
		if res.Err != nil {
			//fmt.Printf("MPLA 2.5 %v\n", res.Err)
			return res.Err
		}
		sidx := *res.LabelKeyIndex
		for sidx < targetIndex {
			//fmt.Printf("sidx=%v targetIndex=%v\n", sidx, targetIndex)
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelKeyP(subctx, dest.Keccak256HI(), sidx)
				if serr != nil {
					//fmt.Printf("MPLA 2.8 %v\n", serr)
					return serr
				}
				if secret == nil {
					panic("Unexpected nil secret")
				}
				secretCache[sidx] = secret
			}
			sidx++
		}
		//fmt.Printf("MPLA 3\n")
		dctx := NewEngineDecryptionContext(e)
		dctx.SetPartitionSecrets(secretCache)
		//fmt.Printf("MPLA 3.4\n")
		e.partitionMutex.Lock()
		//fmt.Printf("MPLA 3.5\n")
		if res.A != nil {
			//When we parse the attestation here, it is for a given set of
			//partition keys available in the engine. The keys can't change because
			//we hold the mutex
			//fmt.Printf("starting decode that should succeed\n")
			rpa, err := iapi.ParseAttestation(subctx, &iapi.PParseAttestation{
				Attestation:       res.A,
				DecryptionContext: dctx,
			})
			if err != nil {
				panic(err)
			}

			//fmt.Printf("MPLA 4\n")
			//The dot will either
			// stay pending
			// move to labelled
			// move to active
			//if it is moving to labelled it must happen while we still hold the
			//partitionmutex
			if rpa.IsMalformed {
				e.partitionMutex.Unlock()
				//fmt.Printf("MPLA 5\n")
				if err := e.ws.MoveAttestationMalformedP(e.ctx, res.A.Keccak256HI()); err != nil {
					return err
				}
				continue
			}
			if rpa.Attestation == nil {
				e.partitionMutex.Unlock()
				panic("nil attestation not malformed?")
			}
			if rpa.Attestation.DecryptedBody != nil {
				//fmt.Printf(">MPLA 6 decrypted body\n")
				e.partitionMutex.Unlock()
				//DOT is transitioning to active
				if err := e.insertActiveAttestation(rpa.Attestation); err != nil {
					//fmt.Printf("MPLA 7\n")
					return err
				}
				//fmt.Printf("<MPLA 6\n")
				continue
			}
			//fmt.Printf("MPLA 7\n")
			if _, ok := rpa.ExtraInfo.(*iapi.WR1Extra); ok {
				//This is a WR1 dot that has been labelled, transition to labelled
				//fmt.Printf("moving the att to labelled\n")
				//sub, _ := rpa.Attestation.Subject()
				//fmt.Printf("moving att to ...%x to labelled %s\n", sub.Multihash()[25:], iapi.WR1PartitionToIntString(rpa.ExtraInfo.(*iapi.WR1Extra).Partition))
				if err := e.ws.MoveAttestationLabelledP(subctx, rpa.Attestation); err != nil {
					return err
				}
				//This is the whole reason for the partition mutex, the att must be
				//atomically compared against all partition keys and inserted if it
				//fails
				e.partitionMutex.Unlock()
				continue
			}
			e.partitionMutex.Unlock()
			//This attestation failed to decrypt at all
			//update the secret key index if we are not direct
			//fmt.Printf("att did not decode\n")
			if !isdirect {
				if err := e.ws.UpdateAttestationPendingP(e.ctx, rpa.Attestation, targetIndex); err != nil {
					return err
				}
			}
			continue
		} //this is an attestation
		if res.N != nil {
			//fmt.Printf("parsing ND again in lab->active\n")
			rpn, err := iapi.ParseNameDeclaration(subctx, &iapi.PParseNameDeclaration{
				NameDeclaration: res.N,
				Dctx:            dctx,
			})
			if err != nil {
				panic(err)
			}
			if rpn.IsMalformed {
				//fmt.Printf("MPLA 5\n")
				if err := e.ws.MoveNameDeclarationMalformedP(e.ctx, res.N.Keccak256HI()); err != nil {
					return err
				}
				e.partitionMutex.Unlock()
				continue
			}
			if rpn.Result.Decoded() {
				e.partitionMutex.Unlock()
				//fmt.Printf("ND decoded\n")

				err := e.insertActiveNameDeclaration(e.ctx, res.N)
				if err != nil {
					return err
				}

				continue
			}
			if rpn.Result.WR1Extra != nil && rpn.Result.WR1Extra.Partition != nil {
				//It has been labelled
				e.partitionMutex.Unlock()
				if err := e.ws.MoveNameDeclarationLabelledP(e.ctx, res.N); err != nil {
					return err
				}
				continue
			}
			//We failed to make any headway, update key index
			if !isdirect {
				if err := e.ws.UpdateNameDeclarationPendingP(e.ctx, res.N, targetIndex); err != nil {
					e.partitionMutex.Unlock()
					return err
				}
				e.partitionMutex.Unlock()
			} else {
				e.partitionMutex.Unlock()
			}
			continue
		}
		//ND
	} //next pending attestation
	//fmt.Printf("MPLA X\n")
	return nil
}

func (e *Engine) insertActiveNameDeclaration(ctx context.Context, nd *iapi.NameDeclaration) error {
	err := e.ws.MoveNameDeclarationActiveP(e.ctx, nd)
	if err != nil {
		return err
	}
	entity, validity, err := e.LookupEntity(ctx, nd.Subject, nd.SubjectLocation)
	if err != nil {
		return err
	}
	if validity.Valid {
		err := e.ws.MoveEntityInterestingP(ctx, entity, nd.SubjectLocation)
		if err != nil {
			return err
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
func (e *Engine) insertKeyAndUnlockLabelled(ent *iapi.Entity, key iapi.SlottedSecretKey) (map[[32]byte]*iapi.Attestation, error) {
	//the rule is: this key must be compared agaisnt all labelled dots and inserted
	//in the database before any further labelled dots can be inserted (no racing)
	//i.e lock, compare labelled, collate list of new active,
	//move old labelled to active, insert key, unlock, return new active for key processing
	//we don't insert the new actives because they too contain keys so must be handled carefully
	//Before we insert the key, we need to ensure we process all labelled dots
	//that it might match (under mutex)
	//edit: I think we have to insert the key before we try processing the labelled
	//      dots. I don't think the order matters because we hold the lock?
	rv := make(map[[32]byte]*iapi.Attestation)
	e.partitionMutex.Lock()
	defer e.partitionMutex.Unlock()
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()

	//Insert the key before processing, to ensure it is available to ParseX
	err := e.ws.InsertWR1KeysForP(ctx, ent.Keccak256HI(), key)
	if err != nil {
		return nil, err
	}

	dctx := NewEngineDecryptionContext(e)
	//fmt.Printf("looking for labelled on ...%x : %s\n", ent.Keccak256HI().Multihash()[25:], iapi.WR1PartitionToIntString(key.Slots()))
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
		//fmt.Printf("insert key unlock labelled proc: %x\n", rpa.Attestation.CanonicalForm.OuterSignature.Content.(serdes.Ed25519OuterSignature).Signature[0:4])
		if rpa.Attestation.DecryptedBody != nil {
			rv[rpa.Attestation.ArrayKeccak256()] = rpa.Attestation
			err := e.moveAttestationToActiveWithoutProcessingKeys(rpa.Attestation)
			if err != nil {
				return nil, err
			}
		} else {
			//	panic("we expected the dot to decrypt with the given key")
		}
	}
	for nd := range e.ws.GetLabelledNameDeclarationsP(ctx, ent.Keccak256HI(), key.Slots()) {
		rnd, err := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
			NameDeclaration: nd.NameDeclaration,
			Dctx:            dctx,
		})
		if err != nil {
			panic(err)
		}
		if rnd.IsMalformed {
			err := e.ws.MoveNameDeclarationMalformedP(ctx, nd.NameDeclaration.Keccak256HI())
			if err != nil {
				return nil, err
			}
			continue
		}
		if rnd.Result.Decoded() {
			err := e.ws.MoveNameDeclarationActiveP(ctx, nd.NameDeclaration)
			if err != nil {
				return nil, err
			}
		}
	}

	//Release mutex
	return rv, nil
}

type recursiveKey struct {
	K        iapi.SlottedSecretKey
	Attester *iapi.Entity
}

//As we move dots from labelled, we get keys. This tries to be a little efficient
//in not trying the exact same key more than once
func (e *Engine) recursiveInsertKeyAndMoveLabelled(ent *iapi.Entity, newkey iapi.SlottedSecretKey) error {
	keysToProcess := make(map[[32]byte]recursiveKey)
	keysToProcess[newkey.IdHash()] = recursiveKey{
		K:        newkey,
		Attester: ent,
	}
	for len(keysToProcess) > 0 {
		for h, key := range keysToProcess {
			delete(keysToProcess, h)
			newDots, err := e.insertKeyAndUnlockLabelled(key.Attester, key.K)
			if err != nil {
				return err
			}
			// XXX this does not seem right: the new dots are going to be dots
			// granted TO the entity that we just unlocked labelled. But
			//if we put them in keysToProcess we will call insertKey with
			//the TO entity instead of the FROM entity!
			for _, d := range newDots {
				attesterhi, attesterloc, err := d.Attester()
				if err != nil {
					panic("expected attester to be available")
				}
				attester, validity, err := e.LookupEntity(e.ctx, attesterhi, attesterloc)
				if !validity.Valid {
					//I would expect this not to have shown up here at all
					continue
				}

				kz := d.WR1SecretSlottedKeys()
				for _, k := range kz {
					keysToProcess[k.IdHash()] = recursiveKey{
						Attester: attester,
						K:        k,
					}
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
	//fmt.Printf("XIAA 0\n")
	fmt.Printf("inserting active attestation\n")
	val, err := e.CheckAttestation(e.ctx, d)
	if err != nil {
		return err
	}
	if !val.Valid {
		fmt.Printf("XX 10\n")
	}
	_, err = e.checkAttestationAndSave(e.ctx, d, val)
	if err != nil {
		return err
	}
	if val.Revoked {
		return nil
	}
	attesterHI, attesterLoc, err := d.Attester()
	if err != nil {
		return err
	}
	attester, _, err := e.LookupEntity(context.Background(), attesterHI, attesterLoc)
	if err != nil {
		return err
	}
	//Make sure the storage knows the attester is interesting
	err = e.ws.MoveEntityInterestingP(e.ctx, attester, attesterLoc)
	if err != nil {
		return err
	}
	//Process the label keys
	for _, k := range d.WR1DomainVisibilityKeys() {
		_, err := e.ws.InsertPartitionLabelKeyP(e.ctx, attesterHI, k)
		if err != nil {
			//fmt.Printf("IAA 5\n")
			return err
		}
	}
	//fmt.Printf("XIAA 4\n")
	for _, k := range d.WR1SecretSlottedKeys() {
		err := e.recursiveInsertKeyAndMoveLabelled(attester, k)
		if err != nil {
			//fmt.Printf("IAA 6\n")
			return err
		}
	}
	//fmt.Printf("IAA 7\n")
	err = e.ws.MoveAttestationActiveP(e.ctx, d)
	if err != nil {
		//fmt.Printf("IAA 8\n")
		return err
	}

	//This must also queue for resync the granting entity. This will take care of the
	//new dots that can move from pending to labelled (and we just took care of
	//the ones alreay in labelled that moved to active)
	//fmt.Printf("IAA 9\n")
	return e.MarkEntityInterestingAndQueueForSync(attester, attesterLoc)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop
func (e *Engine) insertPendingAttestation(d *iapi.Attestation) error {
	//We can't check entities, but we can ensure its not revoked
	val, err := e.CheckAttestation(e.ctx, d)
	if !val.Valid {
		fmt.Printf("XX 20\n")
	}
	okay, err := e.checkPendingAttestationAndSave(e.ctx, d, val)
	if err != nil {
		return err
	}
	if !okay {
		return nil
	}

	return e.ws.MoveAttestationPendingP(e.ctx, d, 0)
}

//Learned OOB or something
//Note this must be thread safe as it is called externally, not
//from the engine's main loop. if resyncDestination is called,
//the dst will be asynchronously brought up to date
//to ensure this new dot is decrypted if possible
func (e *Engine) insertPendingAttestationSync(d *iapi.Attestation, resyncDestination bool) error {
	err := e.insertPendingAttestation(d)
	if err != nil {
		return err
	}
	if resyncDestination {
		dst, _ := d.Subject()
		return e.enqueueEntityResyncIfInteresting(e.ctx, dst)
	}
	return nil
}

func (e *Engine) insertPendingNameDeclaration(nd *iapi.NameDeclaration) error {
	if !nd.Decoded() && (nd.WR1Extra == nil || nd.WR1Extra.Namespace == nil) {
		panic("we need to re-parse this")
	}

	return e.ws.MoveNameDeclarationPendingP(e.ctx, nd, 0)
}
