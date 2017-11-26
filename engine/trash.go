// +build ignore

package engine


//An entity that should be inspected
//Pipeline is IGNORED->INTERESTING
//InsertInterestingEntity(ctx context.Context, hash []byte) error
//GetEntityDOTIndex(ctx context.Context, dst []byte) (int, error)
//SetEntityDOTIndex(ctx context.Context, dst []byte, index int) error

//This will also call InsertOAQUEKeysFor but will add it to the secret log for the VK
//TODO don't add it to the secret log if we already have it
//TODO these signature sucks, update when we do higher levels
//InsertPartitionLabelKeyP(ctx context.Context, dst []byte, ciphertext []byte, partition [][]byte) error
//InsertContentKeyP(ctx context.Context, dst []byte, ciphertext []byte, partition [][]byte) error



//
// func (e *Engine) RecursiveSynchronizeEntity(ctx context.Context, dest *entity.Entity) (err error) {
// 	then := time.Now()
// 	toprocess, err := e.synchronizeEntity(ctx, dest)
// 	//For all sources, synchronize them too
// 	for len(toprocess) > 0 {
// 		for src, _ := range toprocess {
// 			additional, err := e.synchronizeEntity(ctx, src)
// 			if err != nil {
// 				return err
// 			}
// 			for k, v := range additional {
// 				toprocess[k] += v
// 			}
// 			delete(toprocess, src)
// 		}
// 	}
// 	now := time.Now()
// 	delta := now.Sub(then)
// 	if delta > 1*time.Millisecond {
// 		fmt.Printf("RecursiveSync: %s\n", delta)
// 	}
// 	return nil
// }

//TODO loop
// todo we need to use the new features in storage, but first
// we need a list of our interesting entities (for dot rcpt) and
// both types of revocation hash
//This is revocations and so forth
changesToEntityValidity := [][]byte{} //list of entity hashes
changesToDOTValidity := [][]byte{}    //list of dot hashes
entitiesReceivingDOTs := [][]byte{}   //list of dst entity hashes
//TODO get these
//TODO errors here are not impossible (I could imagine a netsplit would
//cause state fetch from light client to error) we need to work out how
//to handle that
for _, revokedEntityHash := range changesToEntityValidity {
  err := e.updateEntityValidity(e.ctx, revokedEntityHash)
  if err != nil {
    panic(fmt.Sprintf("unexpected error updating entity validity: %v", err))
  }
}
for _, revokedDOTHash := range changesToDOTValidity {
  err := e.updateDOTValidity(e.ctx, revokedDOTHash)
  if err != nil {
    panic(fmt.Sprintf("unexpected error updating dot validity: %v", err))
  }
}
for _, triggeredEntityHash := range entitiesReceivingDOTs {
  err := e.updateEntityNewDOTs(e.ctx, triggeredEntityHash)
  if err != nil {
    panic(fmt.Sprintf("unexpected error updating entity dots: %v", err))
  }
}
err := e.PendingTasks(e.ctx)
if err != nil {
  panic(fmt.Sprintf("unexpected error doing pending tasks: %v", err))
}



//This should try decrypt the dot, and insert
//it into any work queues. It should only return an error if
//something abnormal happens and the dot should not be considered
//as processed (i.e processDot should be called again on the same
//ciphertext again). This particular method assumes the DOT is new
//so even if it fails to decrypt, it should be inserted into the database
//for later processing
func (e *Engine) processNewDOT(ctx context.Context, ciphertext []byte, contractDstHash []byte) error {
	sidx, err := e.ws.GetPartitionLabelSecretIndex(ctx, contractDstHash)
	if err != nil {
		return err
	}
	pr, err := dot.DecryptDOT(ctx, ciphertext, e)
	if err != nil {
		return err
	}
	if pr.BadOrMalformed {
		//Do not process the dot, it was submitted badly (is malevolent)
		return nil
	}
	if !bytes.Equal(pr.DOT.PlaintextHeader.DST, contractDstHash) {
		//Do not process the dot, it was submitted badly (is malevolent)
		return nil
	}
	if pr.FullyDecrypted {
		//We fully decoded the dot
		//We need to check if the dot is expired:
		expired, err := pr.DOT.Expired()
		if err != nil {
			//This should not happen
			return err
		}
		if expired {
			err := e.handleExpiredDOT(ctx, pr.DOT)
			if err != nil {
				return err
			}
		}
		//TODO we should stop hitting storage directly for revocations
		//TODO we should have a cache in the engine that gets updated based
		//TODO on the headers
		//Check it for revocations
		revoked, err := e.IsRevoked(ctx, pr.DOT.PlaintextHeader.RevocationHash)
		if err != nil {
			return err
		}
		if revoked {
			err := e.handleRevokedDOT(ctx, pr.DOT)
			if err != nil {
				return err
			}
		}
		//OK this DOT itself seems legit
		//We need to check the SRC and DST entities
		srce, err := e.ws.GetEntityByHash(ctx, pr.DOT.Content.SRC)
		if err != nil {
			return err
		}
		dste, err := e.ws.GetEntityByHash(ctx, pr.DOT.Content.DST)
		if err != nil {
			return err
		}
		//Check them fo
		//We need to trigger a scan of the granting entity's dots.
		e.entitiesRequiringFullScan[wavecrypto.FmtHash(pr.DOT.Content.SRC)] = true
		if err := e.ws.InsertInterestingEntity(ctx, pr.DOT.Content.SRC); err != nil {
			return err
		}
		return e.ws.InsertDOT(ctx, pr.DOT)
	}
	if pr.PartitionDecrypted {
		//We decoded the partition, but not the dot itself
		return e.ws.InsertPendingDOTWithPartition(ctx, ciphertext, pr.Hash, pr.DOT.PlaintextHeader.DST, pr.DOT.PartitionLabel)
	}
	//We did not decode the dot, but we think we may be interested in it
	//going forward
	return e.ws.InsertPendingDOT(ctx, ciphertext, pr.Hash, pr.DOT.PlaintextHeader.DST, sidx)
}


//DOTs can be in the following states:
// unknown (they have a VK+Index greater than we have processed)
// pending (we have them in our DB but could not decrypt it)
// pending with label (we know the partition label but could not decrypt partition)
// decrypted
//Entities can be in the following states:
// unknown we ignore everything to do with this entity
// interesting we process all dots to this entity

//This will bring up to date new entities that have been deemed interesting
//as a result of actions since the last invocation (e.g new dots). This should
//probably be called after every new set of dots processed
func (e *Engine) pendingTasks(ctx context.Context) error {
	e.fullScanMu.Lock()
	defer e.fullScanMu.Unlock()
	for entity, _ := range e.entitiesRequiringFullScan {
		entityVK, err := wavecrypto.UnFmtKey(entity)
		if err != nil {
			return err
		}
		if err := e.updateEntityNewDOTS(ctx, entityVK); err != nil {
			return err
		}
		if err := e.updateEntityPendingDOTs(ctx, entityVK); err != nil {
			return err
		}
	}
	e.entitiesRequiringFullScan = make(map[string]bool)
	return nil
}

// type DecryptionContext interface {
// 	OurOAQUEKey(vk []byte) oaque.MasterKey
// 	OAQUEParamsForVK(vk []byte) *oaque.Params
// 	OAQUEPartitionKeysFor(vk []byte) []*oaque.PrivateKey
// 	OAQUEDelegationKeyFor(vk []byte, partition string) *oaque.PrivateKey
// 	OurSK(vk []byte) []byte
// }


//For a given DSTVK, bring all the pending dots up to date with any new partition label
//secrets. This should be called when we suspect this is actually required. For all
//the pending dots, we will try decrypt the partition label and if successful, queue
//it for decryption with the partition key (or decrypt it immediately)
func (e *Engine) processPartitionLabelSecrets(ctx context.Context, dsthash []byte) error {
	targetIndex, err := e.ws.GetPartitionLabelSecretIndex(ctx, dsthash)
	if err != nil {
		return err
	}
	secretCache := make(map[int]*localdb.Secret)
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for res := range e.ws.GetPendingDOTs(subctx, dsthash) {
		if res.Err != nil {
			return res.Err
		}
		sidx := *res.SecretIndex
		for sidx < targetIndex {
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelSecret(ctx, dsthash, sidx)
				if serr != nil {
					return serr
				}
				if secret == nil {
					panic("Unexpected nil secret")
				}
				secretCache[sidx] = secret
			}
		}
		decodeResult, err := dot.DecryptDOT(ctx, res.Ciphertext, e.decryptionContextWithPartitionKeys(secretCache))
		if err != nil {
			return err
		}
		if decodeResult.BadOrMalformed {
			//New information leads us to believe we must delete this dot
			if err := e.ws.RemovePendingDOT(ctx, res.Hash, dstvk); err != nil {
				return err
			}
		} else if decodeResult.FullyDecrypted {
			//Great, lets add it to the pool
			if err := e.ws.InsertDOT(ctx, decodeResult.DOT); err != nil {
				return err
			}
			//And remove it from pending list
			if err := e.ws.RemovePendingDOT(ctx, res.Hash, dstvk); err != nil {
				return err
			}
		} else if decodeResult.PartitionDecrypted {
			//We need to move this dot to partition decrypted
			if err := e.ws.InsertPendingDOTWithPartition(ctx, res.Ciphertext, res.Hash, dstvk, decodeResult.DOT.PartitionLabel); err != nil {
				return err
			}
			if err := e.ws.RemovePendingDOT(ctx, res.Hash, dstvk); err != nil {
				return err
			}
		} else {
			//We failed to decrypt it
			//We need to update the secret index
			if err := e.ws.UpdatePendingDOTSecretIndex(ctx, res.Hash, dstvk, targetIndex); err != nil {
				return err
			}
		}
	}
}


type Slots [][]byte

//Called by constructor to populate the interesting list arrays
// func (e *Engine) initInterestingLists() {
// 	//First do the entities
// 	for ier := range e.ws.GetInterestingEntities(ctx) {
// 		if ier.Err != nil {
// 			return nil, ier.Err
// 		}
// 		//Also fetch the entity object to grab the revocation hash
// 		ent, err := e.ws.GetEntityByHash(ctx, ier.Hash)
// 		if err != nil {
// 			return nil, err
// 		}
// 		if ent == nil {
// 			panic("do we expect to be unable to resolve this?")
// 		}
// 		//check these entities as we load em up
// 		if ent.Expired() {
// 			err = e.handleExpiredEntity(ctx, ent)
// 			if err != nil {
// 				return nil, err
// 			}
// 			continue
// 		}
// 		rvk, err := e.st.RetrieveRevocation(ctx, ent.RevocationHash)
// 		if err != nil {
// 			return nil, err
// 		}
// 		if rvk != nil {
// 			err = e.handleRevokedEntity(ctx, ent)
// 			if err != nil {
// 				return nil, err
// 			}
// 			continue
// 		}
// 		//Entity still seems valid, lets add it to our interest list
// 		//so we get updates about its status going forward
// 		e.interestingEntities = append(e.interestingEntities, ent.Hash
// 		e.interestingEntityRevocationHashes = append(e.interestingEntityRevocationHashes, ent.RevocationHash)
// 	}
// 	//Then do the dots
// 	//TODO the number of interesting dots could be very large, so I am not sure
// 	//we want to do it this way for dots. We will verify the validity of
// 	//dots we use or receive anyway, so I think this is ok to skip
// }


//
// func (e *Engine) OurOAQUEKey(vk []byte) oaque.MasterKey {
// 	return e.masterOAQUEKeys[wavecrypto.FmtKey(vk)]
// }
// func (e *Engine) OAQUEParamsForVK(ctx context.Context, vk []byte) (*oaque.Params, error) {
// 	if ctx.Err() != nil {
// 		return nil, ctx.Err()
// 	}
// 	blob, err := e.ws.GetOAQUEParamsForVK(ctx, vk)
// 	if err != nil {
// 		return nil, err
// 	}
// 	rv := &oaque.Params{}
// 	rv, ok := rv.Unmarshal(blob)
// 	if !ok {
// 		return nil, fmt.Errorf("failed to unmarshal params object")
// 	}
// 	return rv, nil
// }


// }
// func (e *Engine) OAQUEPartitionKeysFor(ctx context.Context, vk []byte) ([]*oaque.PrivateKey, error) {
// 	if ctx.Err() != nil {
// 		return nil, ctx.Err()
// 	}
// 	blobs, err := e.ws.GetOAQUEPartitionKeysFor(ctx, vk)
// 	if err != nil {
// 		return nil, err
// 	}
// 	rv := make([]*oaque.PrivateKey, len(blobs))
// 	for idx, blob := range blobs {
// 		pk := &oaque.PrivateKey{}
// 		var ok bool
// 		pk, ok = pk.Unmarshal(blob)
// 		if !ok {
// 			return nil, fmt.Errorf("Could not unmarshal private key")
// 		}
// 		rv[idx] = pk
// 	}
// 	return rv, nil
// }
//
// //TODO: represent partition as slots properly
//
// func (e *Engine) OAQUEDelegationKeyFor(ctx context.Context, vk []byte, partition string) (*oaque.PrivateKey, error) {
// 	if ctx.Err() != nil {
// 		return nil, ctx.Err()
// 	}
// 	blob, err := e.ws.GetOAQUEDelegationKeyFor(ctx, vk, partition)
// 	if err != nil {
// 		return nil, err
// 	}
// 	pk := &oaque.PrivateKey{}
// 	var ok bool
// 	pk, ok = pk.Unmarshal(blob)
// 	if !ok {
// 		return nil, fmt.Errorf("Could not unmarshal private key")
// 	}
// 	return pk, nil
// }


// type processResult struct {
// 	Discard   bool
// 	Decoded   bool
// 	Hash      []byte
// 	Partition [][]byte
// 	DOT       *dot.DOT
// }
//
// func (e *Engine) processDOT(ctx context.Context, ciphertext []byte, contractDstVK []byte) (*dot.DecryptionResult, error) {
//
// 	//func DecryptDOT(ctx context.Context, blob []byte, dctx DecryptionContext) (*DecryptionResult, error) {
//   return
// 	result, err := dot.DecryptDOT(ctx, ciphertext, e)
// 	if err != nil {
// 		return nil, err
// 	}
// 	rv := &processResult{
// 		Discard: result.BadOrMalformed,
// 		Decoded: result.FullyDecrypted,
// 	}
// 	if rv.Discard {
// 		return rv, nil
// 	}
// 	if result.PartitionDecrypted {
// 		rv.Partition = result.DOT.PartitionLabel
// 	}
// 	rv.DOT = result.DOT
// 	//TODO when processing a not new dot and it comes back as discard, make sure to
// 	//go into the database and delete it
// 	//Only return error if there is some kind of unexpected error and you want this
// 	//operation to be retried later
// 	return rv, nil
// }
