package engine

import (
	"bytes"
	"context"

	wavecrypto "github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/localdb"
)

//This should try decrypt the dot, and insert
//it into any work queues. It should only return an error if
//something abnormal happens and the dot should not be considered
//as processed (i.e processDot should be called again on the same
//ciphertext again). This particular method assumes the DOT is new
//so even if it fails to decrypt, it should be inserted into the database
//for later processing
func (e *Engine) ProcessNewDOT(ctx context.Context, ciphertext []byte, contractDstVK []byte) error {
	sidx, err := e.ws.GetPartitionLabelSecretIndex(ctx, contractDstVK)
	if err != nil {
		return err
	}
	pr, err := dot.DecryptDOT(ctx, ciphertext, e)
	if err != nil {
		return err
	}
	if pr.BadOrMalformed {
		//Do not process the dot, it is bad
		return nil
	}
	if !bytes.Equal(pr.DOT.PlaintextHeader.DSTVK, contractDstVK) {
		//Do not process the dot, it was submitted badly
		return nil
	}
	if pr.FullyDecrypted {
		//We fully decoded the dot
		//We need to trigger a scan of the granting entity's dots.
		e.entitiesRequiringFullScan[wavecrypto.FmtKey(pr.DOT.Content.SRCVK)] = true
		if err := e.ws.InsertInterestingEntity(ctx, pr.DOT.Content.SRCVK); err != nil {
			return err
		}
		return e.ws.InsertDOT(ctx, pr.DOT)
	}
	if pr.PartitionDecrypted {
		//We decoded the partition, but not the dot itself
		return e.ws.InsertPendingDOTWithPartition(ctx, ciphertext, pr.Hash, pr.DOT.PlaintextHeader.DSTVK, pr.DOT.PartitionLabel)
	}
	//We did not decode the dot, but we think we may be interested in it
	//going forward
	return e.ws.InsertPendingDOT(ctx, ciphertext, pr.Hash, pr.DOT.PlaintextHeader.DSTVK, sidx)
}

type Slots [][]byte

//This will bring up to date new entities that have been deemed interesting
func (e *Engine) PendingTasks(ctx context.Context) error {
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
	return nil
}

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
//secrets. This should be called when we suspect this is actually required
func (e *Engine) processPartitionLabelSecrets(ctx context.Context, dstvk []byte) error {
	targetIndex, err := e.ws.GetPartitionLabelSecretIndex(ctx, dstvk)
	if err != nil {
		return err
	}
	secretCache := make(map[int]*localdb.Secret)
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for res := range e.ws.GetPendingDOTs(subctx, dstvk) {
		if res.Err != nil {
			return res.Err
		}
		sidx := *res.SecretIndex
		for sidx < targetIndex {
			secret, ok := secretCache[sidx]
			if !ok {
				var serr error
				secret, serr = e.ws.GetPartitionLabelSecret(ctx, dstvk, sidx)
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

//The caller must determine that we are actually interested in updating the
//given entity's pending dots.
func (e *Engine) UpdateEntityPendingDOTs(ctx context.Context, vk []byte) error {

}

//The caller must determine that we are actually interested in updating the
//given entity's dots. This pulls from the blockchain if required.
func (e *Engine) UpdateEntityNewDOTS(ctx context.Context, vk []byte) error {
	// Update the dots
	index, err := e.ws.GetEntityDOTIndex(ctx, vk)
	if err != nil {
		return err
	}
	indexChanged := false
	for {
		dotreg, _, err := e.st.RetrieveDOTByVKIndex(ctx, vk, index)
		if dotreg == nil {
			//index already points to next (waiting)
			break
		}
		err = e.ProcessNewDOT(ctx, dotreg.Data, dotreg.DstVK)
		if err != nil {
			return err
		}

		index++
		indexChanged = true
		if index == dotreg.MaxIndex {
			break
		}
	}
	if indexChanged {
		return e.ws.SetEntityDOTIndex(ctx, vk, index)
	}
	return nil
}

func (e *Engine) UpdateEntityMisc(ctx context.Context, vk []byte) error {
	panic("TODO")
}
