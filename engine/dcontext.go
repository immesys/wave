package engine

import (
	"context"

	"github.com/immesys/wave/iapi"
)

type EngineDecryptionContext struct {
	e                *Engine
	partitionSecrets []iapi.EntitySecretKeySchemeInstance
	verifierKey      iapi.AttestationVerifierKeySchemeInstance
}

var _ iapi.WR1DecryptionContext = &EngineDecryptionContext{}

//The map is just for IBE keys decrypting the partition. The OAQUE keys must come from E
func NewEngineDecryptionContext(e *Engine) *EngineDecryptionContext {
	return &EngineDecryptionContext{e: e}
}

func (dctx *EngineDecryptionContext) SetPartitionSecrets(m map[int]iapi.EntitySecretKeySchemeInstance) {
	dctx.partitionSecrets = make([]iapi.EntitySecretKeySchemeInstance, 0, len(m))
	for _, v := range m {
		dctx.partitionSecrets = append(dctx.partitionSecrets, v)
	}
}
func (dctx *EngineDecryptionContext) SetVerifierKey(k iapi.AttestationVerifierKeySchemeInstance) {
	dctx.verifierKey = k
}
func (dctx *EngineDecryptionContext) WR1VerifierBodyKey(ctx context.Context) iapi.AttestationVerifierKeySchemeInstance {
	return dctx.verifierKey
}
func (dctx *EngineDecryptionContext) WR1OAQUEKeysForContent(ctx context.Context, dst iapi.HashSchemeInstance, slots [][]byte, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	if dctx.e == nil {
		return nil
	}
	return dctx.e.ws.WR1KeysForP(ctx, dst, slots, func(k iapi.SlottedSecretKey) bool {
		return onResult(k)
	})
}
func (dctx *EngineDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst iapi.HashSchemeInstance, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	for _, k := range dctx.partitionSecrets {
		more := onResult(k)
		if !more {
			return nil
		}
	}
	return nil

	// numkeys, ok, err := dctx.e.ws.GetEntityPartitionLabelKeyIndexP(ctx, dst)
	// if !ok || err != nil {
	// 	panic(fmt.Sprintf("%v %v", ok, err))
	// }
	// for i := 0; i < numkeys; i++ {
	// 	k, err := dctx.e.ws.GetPartitionLabelKeyP(ctx, dst, i)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	more := onResult(k)
	// 	if !more {
	// 		return nil
	// 	}
	// }
	// return nil
}
func (dctx *EngineDecryptionContext) WR1DirectDecryptionKey(ctx context.Context, dst iapi.HashSchemeInstance, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	if dctx.e == nil {
		return nil
	}
	if iapi.HashSchemeInstanceEqual(dctx.e.perspective.Entity.Keccak256HI(), dst) {
		dek, err := dctx.e.perspective.WR1DirectDecryptionKey(ctx)
		if err == nil {
			panic(err)
		}
		if dek != nil {
			onResult(dek)
		}
	}
	return nil
}
