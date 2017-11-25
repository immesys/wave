package engine

import (
	"bytes"
	"context"

	wavecrypto "github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot"
	localdb "github.com/immesys/wave/localdb/types"
)

//DOTs can be in the following states:
// unknown (they have a VK+Index greater than we have processed)
// pending (we have them in our DB but could not decrypt it)
// pending with label (we know the partition label but could not decrypt partition)
// decrypted
//Entities can be in the following states:
// unknown we ignore everything to do with this entity
// interesting we process all dots to this entity

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

type Slots [][]byte

//This will bring up to date new entities that have been deemed interesting
//as a result of actions since the last invocation (e.g new dots). This should
//probably be called after every new set of dots processed
func (e *Engine) PendingTasks(ctx context.Context) error {
	e.fullScanMu.Lock()
	defer e.fullScanMu.Unlock()
	for entity, _ := range e.entitiesRequiringFullScan {
		entityVK, err := wavecrypto.UnFmtKey(entity)
		if err != nil {
			return err
		}
		if err := e.UpdateEntityNewDOTS(ctx, entityVK); err != nil {
			return err
		}
		if err := e.UpdateEntityPendingDOTs(ctx, entityVK); err != nil {
			return err
		}
	}
	e.entitiesRequiringFullScan = make(map[string]bool)
	return nil
}

//This will bring up to date all entities marked as interesting in the
//database (a persistent list)
func (e *Engine) UpdateAllInterestingEntities(ctx context.Context) error {
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for res := range e.ws.GetInterestingEntities(subctx) {
		if res.Err != nil {
			return res.Err
		}
		if err := e.UpdateEntityNewDOTS(ctx, res.VK); err != nil {
			return err
		}
		if err := e.UpdateEntityPendingDOTs(ctx, res.VK); err != nil {
			return err
		}
	}
}

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

//This should be run whenever we obtain a new partition secret
//from an entity
func (e *Engine) UpdateEntityPendingWithLabelDOTs(ctx context.Context, dsthash []byte) error {
	//For every pending dot with label
	//Try find the secret and decrypt
}
