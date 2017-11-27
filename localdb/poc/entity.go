package poc

import (
	"context"
	"fmt"

	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/localdb/types"
)

func (p *poc) addRevocationHash(ctx context.Context, isEntity bool, targetHash []byte, rvkHash []byte) error {
	rs := &RevocationState{
		IsEntity:   isEntity,
		TargetHash: targetHash,
	}
	k := p.PKey(ctx, "rvk", ToB64(rvkHash))
	ba, err := rs.MarshalMsg(nil)
	if err != nil {
		return err
	}
	return p.u.Store(ctx, k, ba)
}
func (p *poc) saveEntityState(ctx context.Context, es *EntityState) error {
	k := p.PKey(ctx, "entity", ToB64(es.Entity.Hash))
	ba, err := es.MarshalMsg(nil)
	if err != nil {
		return err
	}
	return p.u.Store(ctx, k, ba)
}
func (p *poc) loadEntity(ctx context.Context, hash []byte) (*EntityState, error) {
	if len(hash) != 32 {
		panic(hash)
	}
	k := p.PKey(ctx, "entity", ToB64(hash))
	ba, err := p.u.Load(ctx, k)
	if err != nil {
		return nil, err
	}
	if ba == nil {
		return nil, nil
	}
	es := &EntityState{}
	_, err = es.UnmarshalMsg(ba)
	if err != nil {
		panic(err)
	}
	return es, nil
}
func (p *poc) moveEntity(ctx context.Context, ent *entity.Entity, state int) error {
	es := &EntityState{
		Entity: ent,
		State:  state,
	}
	err := p.addRevocationHash(ctx, true, ent.Hash, ent.RevocationHash)
	if err != nil {
		return err
	}
	return p.saveEntityState(ctx, es)
}

//Perspective functions
func (p *poc) MoveEntityInterestingP(ctx context.Context, ent *entity.Entity) error {
	//Ensure we are idempotent, don't want to clobber other state
	es, err := p.loadEntity(ctx, ent.Hash)
	if err != nil {
		return err
	}
	//We know about it, probably revoked / expired or already intersting
	if es != nil {
		return nil
	}
	return p.moveEntity(ctx, ent, StateInteresting)
}
func (p *poc) GetInterestingEntitiesP(pctx context.Context) chan types.InterestingEntityResult {
	rv := make(chan types.InterestingEntityResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "entity")
	vch, ech := p.u.LoadPrefixKeys(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			parts := split(v.Key)
			hash := FromB64(parts[len(parts)-1])
			if len(hash) != 32 {
				panic(hash)
			}
			select {
			case rv <- types.InterestingEntityResult{
				Hash: hash,
			}:
			case <-ctx.Done():
				rv <- types.InterestingEntityResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- types.InterestingEntityResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) GetEntityPartitionLabelKeyIndexP(ctx context.Context, dst []byte) (bool, int, error) {
	es, err := p.loadEntity(ctx, dst)
	if err != nil {
		return false, 0, err
	}
	if es == nil {
		panic("we don't know this entity")
	}
	return true, es.MaxLabelKeyIndex, nil
}

func (p *poc) IsEntityInterestingP(ctx context.Context, hash []byte) (bool, error) {
	es, err := p.loadEntity(ctx, hash)
	if err != nil {
		return false, err
	}
	if es == nil {
		return false, nil
	}
	return es.State == StateInteresting, nil
}
func (p *poc) GetEntityDotIndexP(ctx context.Context, hsh []byte) (okay bool, dotIndex int, err error) {
	es, err := p.loadEntity(ctx, hsh)
	if err != nil {
		return false, 0, err
	}
	if es == nil {
		return false, 0, nil
	}
	return true, es.DotIndex, nil
}
func (p *poc) SetEntityDotIndexP(ctx context.Context, hsh []byte, dotIndex int) error {
	es, err := p.loadEntity(ctx, hsh)
	if err != nil {
		return err
	}
	if es == nil {
		return fmt.Errorf("we don't know this entity")
	}
	es.DotIndex = dotIndex
	return p.saveEntityState(ctx, es)
}
func (p *poc) MoveEntityRevokedG(ctx context.Context, ent *entity.Entity) error {
	es, err := p.loadEntity(ctx, ent.Hash)
	if err != nil {
		return err
	}
	if es == nil {
		//we never thought it was interesting anyway
		return nil
	}
	es.State = StateRevoked
	return p.saveEntityState(ctx, es)
}
func (p *poc) MoveEntityExpiredG(ctx context.Context, ent *entity.Entity) error {
	es, err := p.loadEntity(ctx, ent.Hash)
	if err != nil {
		return err
	}
	if es == nil {
		//we never thought it was interesting anyway
		return nil
	}
	es.State = StateExpired
	return p.saveEntityState(ctx, es)
}
func (p *poc) GetEntityByHashG(ctx context.Context, hsh []byte) (*entity.Entity, error) {
	es, err := p.loadEntity(ctx, hsh)
	if err != nil {
		return nil, err
	}
	if es == nil {
		return nil, nil
	}
	return es.Entity, nil
}
