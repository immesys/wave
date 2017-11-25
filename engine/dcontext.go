package engine

import (
	"context"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/entity"
	localdb "github.com/immesys/wave/localdb/types"
)

type EngineDecryptionContext struct {
	e                *Engine
	partitionSecrets []*localdb.Secret
}

func NewEngineDecryptionContext(e *Engine, partitionSecrets map[int]*localdb.Secret) *EngineDecryptionContext {
	rv := &EngineDecryptionContext{e: e}
	rv.partitionSecrets = make([]*localdb.Secret, len(partitionSecrets))
	idx := 0
	for _, v := range partitionSecrets {
		rv.partitionSecrets[idx] = v
		idx++
	}
	return rv
}

//These are only different when restricting the partition label keys
func (dc *EngineDecryptionContext) OAQUEKeysForContent(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return dc.OAQUEKeysFor(ctx, hash, slots, onResult)
}

//We may want to restrict the keys that are available here, because the dot decoding will scan over them and try them all.
//If we have already tried some keys, we don't want to try them again
func (dc *EngineDecryptionContext) OAQUEKeysForPartitionLabel(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	//TODO use secret cache
	return dc.OAQUEKeysFor(ctx, hash, slots, onResult)
}

func (dc *EngineDecryptionContext) EntityFromHash(ctx context.Context, hash []byte) (*entity.Entity, error) {
	return dc.e.ws.GetEntityByHashG(ctx, hash)
}
func (dc *EngineDecryptionContext) OAQUEKeysFor(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	//The given context is not the engine context, so we need to add the perspective to it
	subctx := context.WithValue(ctx, perspectiveKey, dc.e.perspective)
	var err error
	oerr := dc.e.ws.OAQUEKeysForP(subctx, hash, slots, func(k *oaque.PrivateKey) bool {
		return onResult(k)
	})
	if oerr != nil {
		return oerr
	}
	return err
}
