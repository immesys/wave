package poc

import (
	"context"
	"fmt"

	"github.com/immesys/wave/iapi"
)

// func (p *poc) addRevocationHash(ctx context.Context, isEntity bool, targetHash []byte, rvkHash []byte) error {
// 	rs := &RevocationState{
// 		IsEntity:   isEntity,
// 		TargetHash: targetHash,
// 	}
// 	k := p.PKey(ctx, "rvk", ToB64(rvkHash))
// 	ba, err := rs.MarshalMsg(nil)
// 	if err != nil {
// 		return err
// 	}
// 	return p.u.Store(ctx, k, ba)
// }
func (p *poc) saveEntityState(ctx context.Context, es *EntityState) error {
	if len(es.Hash) != 32 {
		panic(es)
	}
	k := p.PKey(ctx, "entity", ToB64(es.Hash))
	ba, err := marshalGob(es)
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
	err = unmarshalGob(ba, es)
	if err != nil {
		panic(err)
	}
	return es, nil
}
func (p *poc) moveEntity(ctx context.Context, ent *iapi.Entity, state int) error {
	es := &EntityState{
		Entity: ent,
		Hash:   ent.Keccak256(),
		State:  state,
	}
	// err := p.addRevocationHash(ctx, true, ent.Hash, ent.RevocationHash)
	// if err != nil {
	// 	return err
	// }
	return p.saveEntityState(ctx, es)
}

//Perspective functions
func (p *poc) MoveEntityInterestingP(ctx context.Context, ent *iapi.Entity) error {
	//Ensure we are idempotent, don't want to clobber other state
	fmt.Printf("thing was: %x\n", ent.Keccak256())
	es, err := p.loadEntity(ctx, ent.Keccak256())
	if err != nil {
		return err
	}
	//We know about it, probably revoked / expired or already intersting
	if es != nil {
		return nil
	}
	return p.moveEntity(ctx, ent, StateInteresting)
}
func (p *poc) GetInterestingEntitiesP(pctx context.Context) chan iapi.InterestingEntityResult {
	rv := make(chan iapi.InterestingEntityResult, 10)
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
			case rv <- iapi.InterestingEntityResult{
				HashSchemeInstance: &iapi.HashSchemeInstance_Keccak_256{hash},
			}:
			case <-ctx.Done():
				rv <- iapi.InterestingEntityResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.InterestingEntityResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) GetEntityPartitionLabelKeyIndexP(ctx context.Context, dsthi iapi.HashSchemeInstance) (bool, int, error) {
	dst := keccakFromHI(dsthi)
	es, err := p.loadEntity(ctx, dst)
	if err != nil {
		return false, 0, err
	}
	if es == nil {
		panic("we don't know this entity")
	}
	return true, es.MaxLabelKeyIndex, nil
}

func (p *poc) IsEntityInterestingP(ctx context.Context, hi iapi.HashSchemeInstance) (bool, error) {
	hash := keccakFromHI(hi)

	es, err := p.loadEntity(ctx, hash)
	if err != nil {
		return false, err
	}
	if es == nil {
		return false, nil
	}
	return es.State == StateInteresting, nil
}
func (p *poc) GetEntityQueueIndexP(ctx context.Context, hi iapi.HashSchemeInstance) (okay bool, dotIndex int, err error) {
	hsh := keccakFromHI(hi)

	es, err := p.loadEntity(ctx, hsh)
	if err != nil {
		return false, 0, err
	}
	if es == nil {
		return false, 0, nil
	}
	return true, es.QueueIndex, nil
}
func (p *poc) SetEntityQueueIndexP(ctx context.Context, hi iapi.HashSchemeInstance, queueIndex int) error {
	hsh := keccakFromHI(hi)
	es, err := p.loadEntity(ctx, hsh)
	if err != nil {
		return err
	}
	if es == nil {
		return fmt.Errorf("we don't know this entity")
	}
	es.QueueIndex = queueIndex
	return p.saveEntityState(ctx, es)
}
func (p *poc) MoveEntityRevokedG(ctx context.Context, ent *iapi.Entity) error {
	es, err := p.loadEntity(ctx, ent.Keccak256())
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
func (p *poc) MoveEntityExpiredG(ctx context.Context, ent *iapi.Entity) error {
	es, err := p.loadEntity(ctx, ent.Keccak256())
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
func (p *poc) GetEntityByHashSchemeInstanceG(ctx context.Context, hi iapi.HashSchemeInstance) (*iapi.Entity, error) {
	hash := keccakFromHI(hi)
	es, err := p.loadEntity(ctx, hash)
	if err != nil {
		return nil, err
	}
	if es == nil {
		return nil, nil
	}
	return es.Entity, nil
}
