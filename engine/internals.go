package engine

import (
	"context"
	"fmt"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	wavecrypto "github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/localdb"
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

type Engine struct {
	ws localdb.WaveState
	st storage.Storage
	//all the SKs that we have
	secretEd25519Keys map[string][]byte
	masterOAQUEKeys   map[string]oaque.MasterKey

	entitiesRequiringFullScan map[string]bool
}

// type DecryptionContext interface {
// 	OurOAQUEKey(vk []byte) oaque.MasterKey
// 	OAQUEParamsForVK(vk []byte) *oaque.Params
// 	OAQUEPartitionKeysFor(vk []byte) []*oaque.PrivateKey
// 	OAQUEDelegationKeyFor(vk []byte, partition string) *oaque.PrivateKey
// 	OurSK(vk []byte) []byte
// }

func (e *Engine) Init() error {
	var err error
	e.secretEd25519Keys, err = e.ws.LoadSecretEd25519Keys()
	if err != nil {
		return err
	}
	e.masterOAQUEKeys, err = e.ws.LoadMasterOAQUEKeys()
	if err != nil {
		return err
	}
	return nil
}

func (e *Engine) OurOAQUEKey(vk []byte) oaque.MasterKey {
	return e.masterOAQUEKeys[wavecrypto.FmtKey(vk)]
}
func (e *Engine) OAQUEParamsForVK(ctx context.Context, vk []byte) (*oaque.Params, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	blob, err := e.ws.GetOAQUEParamsForVK(ctx, vk)
	if err != nil {
		return nil, err
	}
	rv := &oaque.Params{}
	rv, ok := rv.Unmarshal(blob)
	if !ok {
		return nil, fmt.Errorf("failed to unmarshal params object")
	}
	return rv, nil
}

//These are only different when restricting the partition label keys
func (e *Engine) OAQUEKeysForContent(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return e.OAQUEKeysFor(ctx, vk, slots, onResult)
}

func (e *Engine) OAQUEKeysForPartitionLabel(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return e.OAQUEKeysFor(ctx, vk, slots, onResult)
}

func (e *Engine) OAQUEKeysFor(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var err error
	oerr := e.ws.OAQUEKeysFor(ctx, vk, slots, func(k []byte) bool {
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

func (e *Engine) OurSK(vk []byte) []byte {
	return e.secretEd25519Keys[wavecrypto.FmtKey(vk)]
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
