package engine

import (
	"context"
	"fmt"

	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/wve"
)

type EngineDecryptionContext struct {
	e                *Engine
	partitionSecrets []iapi.EntitySecretKeySchemeInstance
	verifierKey      []byte
	proverBodyKey    []byte
	autopopulate     bool
	populated        map[string]bool
}

var _ iapi.WR1DecryptionContext = &EngineDecryptionContext{}

//The map is just for IBE keys decrypting the partition. The OAQUE keys must come from E
func NewEngineDecryptionContext(e *Engine) *EngineDecryptionContext {
	return &EngineDecryptionContext{e: e, populated: make(map[string]bool)}
}

func (dctx *EngineDecryptionContext) SetPartitionSecrets(m map[int]iapi.EntitySecretKeySchemeInstance) {
	dctx.partitionSecrets = make([]iapi.EntitySecretKeySchemeInstance, 0, len(m))
	for _, v := range m {
		dctx.partitionSecrets = append(dctx.partitionSecrets, v)
	}
}
func (dctx *EngineDecryptionContext) AutoLoadPartitionSecrets(v bool) {
	dctx.autopopulate = v
}
func (dctx *EngineDecryptionContext) LoadAllPartitionSecrets(issuer iapi.HashSchemeInstance) wve.WVE {
	dctx.partitionSecrets = make([]iapi.EntitySecretKeySchemeInstance, 0, 64)
	okay, maxindex, err := dctx.e.ws.GetEntityPartitionLabelKeyIndexP(dctx.e.ctx, issuer)
	if err != nil {
		return wve.ErrW(wve.LookupFailure, "could not load partition secrets", err)
	}
	if !okay {
		return wve.Err(wve.LookupFailure, "unknown entity")
	}
	for sidx := 0; sidx < maxindex; sidx++ {
		secret, serr := dctx.e.ws.GetPartitionLabelKeyP(dctx.e.ctx, issuer, sidx)
		if serr != nil {
			return wve.ErrW(wve.LookupFailure, "could not load partition key", serr)
		}
		if secret == nil {
			panic("Unexpected nil secret")
		}
		dctx.partitionSecrets = append(dctx.partitionSecrets, secret)
	}
	return nil
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
func (dctx *EngineDecryptionContext) WR1EntityFromHash(ctx context.Context, hi iapi.HashSchemeInstance, loc iapi.LocationSchemeInstance) (*iapi.Entity, error) {
	ent, val, err := dctx.e.LookupEntity(dctx.e.ctx, hi, loc)
	if err != nil {
		return nil, err
	}
	if !val.Valid {
		return nil, fmt.Errorf("entity is no longer valid")
	}
	return ent, nil
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
		k, err := dctx.e.perspective.WR1BodyKey(dctx.e.ctx, slots)
		if err != nil {
			return err
		}
		onResult(k)
		return nil
	}
	return dctx.e.ws.WR1KeysForP(dctx.e.ctx, dst, slots, onResult)
}
func (dctx *EngineDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst iapi.HashSchemeInstance, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	if dctx.autopopulate {
		if !dctx.populated[dst.MultihashString()] {
			dctx.LoadAllPartitionSecrets(dst)
		}
		dctx.populated[dst.MultihashString()] = true
	}
	//Return the key for our own namespace
	own, err := dctx.e.perspective.WR1LabelKey(ctx, []byte(dctx.e.perspective.Entity.Keccak256HI().MultihashString()))
	if err != nil {
		return err
	}
	if !onResult(own) {
		return nil
	}
	for _, k := range dctx.partitionSecrets {
		more := onResult(k)
		if !more {
			return nil
		}
	}
	return nil
}
func (dctx *EngineDecryptionContext) WR1AttesterDirectDecryptionKey(ctx context.Context, onResult func(k iapi.EntitySecretKeySchemeInstance) bool) error {
	if dctx.e == nil {
		return nil
	}
	dek, err := dctx.e.perspective.WR1DirectDecryptionKey(ctx)
	if err != nil {
		panic(err)
	}
	if dek != nil {
		onResult(dek)
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
func (dctx *EngineDecryptionContext) AttestationByHashLoc(ctx context.Context, hash iapi.HashSchemeInstance, loc iapi.LocationSchemeInstance) (*iapi.Attestation, wve.WVE) {
	att, validity, err := dctx.e.LookupAttestationNoPerspective(ctx, hash, nil, loc)
	_ = validity
	if err != nil {
		return nil, wve.ErrW(wve.LookupFailure, "could not lookup attestation", err)
	}
	return att, nil
}
