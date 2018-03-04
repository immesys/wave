package engine

import (
	"context"

	"github.com/immesys/wave/iapi"
)

type EngineDecryptionContext struct {
	e                *Engine
	partitionSecrets []iapi.EntityKeySchemeInstance
}

//The map is just for IBE keys decrypting the partition. The OAQUE keys must come from E
func NewEngineDecryptionContext(e *Engine, partitionSecrets map[int]iapi.EntitySecretKeySchemeInstance) *EngineDecryptionContext {
	panic("ni")
	/*
		rv := &EngineDecryptionContext{e: e}
		rv.partitionSecrets = make([]*localdb.Secret, len(partitionSecrets))
		idx := 0
		for _, v := range partitionSecrets {
			rv.partitionSecrets[idx] = v
			idx++
		}
		return rv*/
}

func (dc *EngineDecryptionContext) WR1VerifierBodyKey(ctx context.Context) AttestationVerifierKeySchemeInstance {
	panic("ni")
}
func (dc *EngineDecryptionContext) WR1EntityFromHash(ctx context.Context, hash HashScheme) (Entity, error) {
	panic("ni")
}
func (dc *EngineDecryptionContext) WR1OAQUEKeysForContent(ctx context.Context, dst HashScheme, slots [][]byte, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	return nil
}
func (dc *EngineDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashScheme, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	return nil
}

//
// //These are only different when restricting the partition label keys
// func (dc *EngineDecryptionContext) OAQUEKeysForContent(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
// 	return dc.OAQUEKeysFor(ctx, hash, slots, onResult)
// }
//
// //We may want to restrict the keys that are available here, because the dot decoding will scan over them and try them all.
// //If we have already tried some keys, we don't want to try them again
// func (dc *EngineDecryptionContext) OAQUEKeysForPartitionLabel(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
// 	//TODO use secret cache
// 	//If secret cache is nil, don't use it
// 	return dc.OAQUEKeysFor(ctx, hash, slots, onResult)
// }
//
// func (dc *EngineDecryptionContext) EntityFromHash(ctx context.Context, hash []byte) (*entity.Entity, error) {
// 	return dc.e.ws.GetEntityByHashG(ctx, hash)
// }
// func (dc *EngineDecryptionContext) OAQUEKeysFor(ctx context.Context, hash []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
// 	if ctx.Err() != nil {
// 		return ctx.Err()
// 	}
// 	//The given context is not the engine context, so we need to add the perspective to it
// 	subctx := context.WithValue(ctx, PerspectiveKey, dc.e.perspective)
// 	var err error
// 	oerr := dc.e.ws.OAQUEKeysForP(subctx, hash, slots, func(k *oaque.PrivateKey) bool {
// 		return onResult(k)
// 	})
// 	if oerr != nil {
// 		return oerr
// 	}
// 	return err
// }
