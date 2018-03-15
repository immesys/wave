package engine

import (
	"context"

	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/wve"
)

type EngineDecryptionContext struct {
	e                *Engine
	partitionSecrets []iapi.EntitySecretKeySchemeInstance
	verifierKey      []byte
	proverBodyKey    []byte
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
func (dctx *EngineDecryptionContext) SetVerifierKey(k []byte) {
	dctx.verifierKey = k
}
func (dctx *EngineDecryptionContext) WR1VerifierBodyKey(ctx context.Context) []byte {
	return dctx.verifierKey
}
func (dctx *EngineDecryptionContext) SetProverKey(k []byte) {
	dctx.proverBodyKey = k
}
func (dctx *EngineDecryptionContext) WR1ProverBodyKey(ctx context.Context) []byte {
	return dctx.proverBodyKey
}
func (dctx *EngineDecryptionContext) WR1OAQUEKeysForContent(ctx context.Context, dst iapi.HashSchemeInstance, slots [][]byte, onResult func(k iapi.SlottedSecretKey) bool) error {
	if dctx.e == nil {
		return nil
	}
	if iapi.HashSchemeInstanceEqual(dctx.e.perspective.Entity.Keccak256HI(), dst) {
		//This is out perspective entity, generate the direct key
		k, err := dctx.e.perspective.WR1BodyKey(ctx, slots)
		if err != nil {
			return err
		}
		onResult(k)
		return nil
	}
	return dctx.e.ws.WR1KeysForP(ctx, dst, slots, onResult)
}
func (dctx *EngineDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst iapi.HashSchemeInstance, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	for _, k := range dctx.partitionSecrets {
		more := onResult(k)
		if !more {
			return nil
		}
	}
	return nil
}
func (dctx *EngineDecryptionContext) WR1DirectDecryptionKey(ctx context.Context, dst iapi.HashSchemeInstance, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	if dctx.e == nil {
		return nil
	}
	if iapi.HashSchemeInstanceEqual(dctx.e.perspective.Entity.Keccak256HI(), dst) {
		dek, err := dctx.e.perspective.WR1DirectDecryptionKey(ctx)
		if err != nil {
			panic(err)
		}
		if dek != nil {
			onResult(dek)
		}
	}
	return nil
}
func (dctx *EngineDecryptionContext) EntityByHashLoc(ctx context.Context, hash iapi.HashSchemeInstance, loc iapi.LocationSchemeInstance) (*iapi.Entity, wve.WVE) {
	ent, validity, err := dctx.e.LookupEntity(ctx, hash, loc)
	if err != nil {
		return nil, wve.ErrW(wve.LookupFailure, "could not lookup entity", err)
	}
	//Ingore the validity
	_ = validity
	return ent, nil
}
