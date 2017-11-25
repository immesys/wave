package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
	localdb "github.com/immesys/wave/localdb/types"
	"github.com/immesys/wave/storage"
)

//how to develop this?
// guiding principles: we don't take an action based on a new BC event
// but rather based on a task
// BUT we may also trigger some tasks based on observed logs blooms
// in the block headers
// actions:
//  A) update an entity (fields, attestations)
//  B) update dot index (dstvk, index)
//  C) add out-of-band DOT
// b+c will trigger further actions that must get added to the work queue

// When agent first starts, all interesting entities will be updated.
// after that, updates are triggered by header block blooms
// There is one engine per perspective (a perspective is a controlling entity)
type Engine struct {
	ctx context.Context
	ws  localdb.WaveState
	st  storage.Storage
	//all the SKs that we have
	perspective *entity.Entity

	entitiesRequiringFullScan map[string]bool
	fullScanMu                sync.Mutex
}

// type DecryptionContext interface {
// 	OurOAQUEKey(vk []byte) oaque.MasterKey
// 	OAQUEParamsForVK(vk []byte) *oaque.Params
// 	OAQUEPartitionKeysFor(vk []byte) []*oaque.PrivateKey
// 	OAQUEDelegationKeyFor(vk []byte, partition string) *oaque.PrivateKey
// 	OurSK(vk []byte) []byte
// }

func NewEngine(ctx context.Context, state localdb.WaveState, bchain storage.Storage, perspective *entity.Entity) (*Engine, error) {
	var err error
	rv := Engine{
		ctx:                       ctx,
		ws:                        state,
		st:                        bchain,
		perspective:               perspective,
		entitiesRequiringFullScan: make(map[string]bool),
	}
	go rv.watchHeaders()
	return &rv, nil
}

// For as long as the engine's context is active, watch and process new
// events on the chain
func (e *Engine) watchHeaders() {
	//TODO loop
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

}

//There is reason to believe the given entity may have been revoked or
//expired, check with storage and take care of it if it has
func (e *Engine) updateEntityValidity(ctx context.Context, enthash []byte) error {
	panic("notimp")
}
func (e *Engine) updateDOTValidity(ctx context.Context, dothash []byte) error {
	panic("notimp")
}

//This looks in the chain for new dots to an entity since we last checked it
//it is idempotent and will also trigger reprocessing of any other unlocked
//dots
func (e *Engine) updateEntityNewDOTs(ctx context.Context, enthash []byte) error {
	// Update the dots
	index, err := e.ws.GetEntityDOTIndex(ctx, enthash)
	if err != nil {
		return err
	}
	indexChanged := false
	for {
		dotreg, _, err := e.st.RetrieveDOTByEntityIndex(ctx, enthash, index)
		if dotreg == nil {
			//index already points to next (waiting)
			break
		}
		err = e.processNewDOT(ctx, dotreg.Data, dotreg.DstHash)
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
		return e.ws.SetEntityDOTIndex(ctx, enthash, index)
	}
	return nil
}

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

//These are only different when restricting the partition label keys
func (e *Engine) OAQUEKeysForContent(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return e.OAQUEKeysFor(ctx, hash, slots, onResult)
}

func (e *Engine) OAQUEKeysForPartitionLabel(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return e.OAQUEKeysFor(ctx, hash, slots, onResult)
}

func (e *Engine) OAQUEKeysFor(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var err error
	oerr := e.ws.OAQUEKeysFor(ctx, hash, slots, func(k []byte) bool {
		pk := &oaque.PrivateKey{}
		var ok bool
		pk, ok = pk.Unmarshal(k)
		if !ok {
			err = fmt.Errorf("could not unmarshal private key")
			return false
		}
		return onResult(pk)
	})
	if oerr != nil {
		return oerr
	}
	return err
}

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

func (e *Engine) decryptionContextWithPartitionKeys(keys map[int]*localdb.Secret) dot.DecryptionContext {
	//?
	return nil //TODO
}

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
