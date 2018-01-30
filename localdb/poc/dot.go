package poc

import (
	"bytes"
	"context"

	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/localdb/types"
)

func (p *poc) saveDotState(ctx context.Context, ds *DotState) error {
	k := p.PKey(ctx, "dot", ToB64(ds.Dot.Hash))
	ba, err := ds.MarshalMsg(nil)
	if err != nil {
		return err
	}
	return p.u.Store(ctx, k, ba)
}
func (p *poc) loadDotState(ctx context.Context, hash []byte) (*DotState, error) {
	k := p.PKey(ctx, "dot", ToB64(hash))
	ba, err := p.u.Load(ctx, k)
	if err != nil {
		return nil, err
	}
	if ba == nil {
		return nil, nil
	}
	ds := &DotState{}
	_, err = ds.UnmarshalMsg(ba)
	if err != nil {
		panic(err)
	}
	return ds, nil
}

func (p *poc) setDotStateField(ctx context.Context, dh []byte, state int) error {
	ds, err := p.loadDotState(ctx, dh)
	if err != nil {
		return err
	}
	if ds == nil {
		//We don't care anyway
		return nil
	}
	ds.State = state
	return p.saveDotState(ctx, ds)
}

//Note that we are treating this as a P function here, but it doesn't
//really matter
func (p *poc) MoveDotRevokedG(ctx context.Context, dot *dot.DOT) error {
	return p.setDotStateField(ctx, dot.Hash, StateRevoked)
}
func (p *poc) GetDotP(ctx context.Context, hash []byte) (d *dot.DOT, err error) {
	ds, err := p.loadDotState(ctx, hash)
	if err != nil {
		return nil, err
	}
	if ds == nil {
		//We don't care anyway
		return nil, nil
	}
	return ds.Dot, nil
}
func (p *poc) MoveDotMalformedP(ctx context.Context, hash []byte) error {
	return p.setDotStateField(ctx, hash, StateMalformed)
}
func (p *poc) MoveDotExpiredP(ctx context.Context, dt *dot.DOT) error {
	return p.setDotStateField(ctx, dt.Hash, StateExpired)
}
func (p *poc) MoveDotEntRevokedP(ctx context.Context, dt *dot.DOT) error {
	return p.setDotStateField(ctx, dt.Hash, StateEntRevoked)
}
func (p *poc) GetInterestingByRevocationHashP(pctx context.Context, rvkhash []byte) chan types.ReverseLookupResult {
	rv := make(chan types.ReverseLookupResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "rvk")
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			rs := &RevocationState{}
			_, err := rs.UnmarshalMsg(v.Value)
			if err != nil {
				panic(err)
			}
			rlr := types.ReverseLookupResult{
				Hash:  rs.TargetHash,
				IsDOT: !rs.IsEntity,
			}
			if rs.IsEntity {
				ent, err := p.loadEntity(ctx, rs.TargetHash)
				if err != nil {
					panic(err)
				}
				if ent == nil {
					panic("expected to find this")
				}
				rlr.Entity = ent.Entity
			} else {
				dot, err := p.loadDotState(ctx, rs.TargetHash)
				if err != nil {
					panic(err)
				}
				if dot == nil {
					panic("expected to find this")
				}
				rlr.Dot = dot.Dot
			}
			select {
			case rv <- rlr:
			case <-ctx.Done():
				rv <- types.ReverseLookupResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- types.ReverseLookupResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) MoveDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error {
	ds, err := p.loadDotState(ctx, dt.Hash)
	if err != nil {
		return err
	}
	if ds != nil {
		panic("we moved a dot into pending when we already knew about it?")
	}
	ds = &DotState{
		State:         StatePending,
		Dot:           dt,
		LabelKeyIndex: labelKeyIndex,
	}
	return p.saveDotState(ctx, ds)
}
func (p *poc) UpdateDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error {
	ds, err := p.loadDotState(ctx, dt.Hash)
	if err != nil {
		return err
	}
	if ds == nil {
		panic("trying to update lki on nonexistent dot")
	}
	if ds.State != StatePending {
		panic("trying to update lki on dot not pending")
	}
	if labelKeyIndex <= ds.LabelKeyIndex {
		panic("label key index is LTE the current one")
	}
	ds.LabelKeyIndex = labelKeyIndex
	return p.saveDotState(ctx, ds)
}
func (p *poc) GetPendingDotsP(pctx context.Context, dst []byte, lkiLT int) chan types.PendingDOTResult {
	rv := make(chan types.PendingDOTResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "dot")
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			ds := &DotState{}
			_, err := ds.UnmarshalMsg(v.Value)
			if err != nil {
				panic(err)
			}
			if ds.LabelKeyIndex >= lkiLT {
				continue
			}
			pdr := types.PendingDOTResult{
				Dot:           ds.Dot,
				Hash:          ds.Dot.Hash,
				LabelKeyIndex: &ds.LabelKeyIndex,
			}
			select {
			case rv <- pdr:
			case <-ctx.Done():
				rv <- types.PendingDOTResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- types.PendingDOTResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) MoveDotLabelledP(ctx context.Context, dt *dot.DOT) error {
	err := p.insertPartitionToDotLink(ctx, dt.DST.Hash, dt.PartitionLabel, dt)
	if err != nil {
		return err
	}
	ds := &DotState{
		State: StateLabelled,
		Dot:   dt,
	}
	return p.saveDotState(ctx, ds)
}
func (p *poc) insertActiveDotForwardLink(ctx context.Context, dt *dot.DOT) error {
	k := p.PKey(ctx, "fdot", ToB64(dt.SRC.Hash), ToB64(dt.Hash))
	//We don't really need a value
	return p.u.Store(ctx, k, []byte{1})
}
func (p *poc) MoveDotActiveP(ctx context.Context, dt *dot.DOT) error {
	err := p.insertActiveDotForwardLink(ctx, dt)
	if err != nil {
		return err
	}
	ds := &DotState{
		State: StateActive,
		Dot:   dt,
	}
	return p.saveDotState(ctx, ds)
}

// func (p *poc) GetPartitionLabelKeyIndexP(ctx context.Context, dst []byte) (bool, int, error) {
// 	ds, err := p.loadDotState(ctx, dst)
// 	if err != nil {
// 		return false, 0, err
// 	}
// 	if ds == nil {
// 		return false, 0, nil
// 	}
// 	if ds.State != StatePending {
// 		panic("trying to query lki on dot not pending")
// 	}
// 	return true, ds.LabelKeyIndex, nil
// }

//TODO we are not properly cancelling context if there is error
func (p *poc) GetActiveDotsFromP(pctx context.Context, src []byte, filter *types.LookupFromFilter) chan types.LookupFromResult {
	rv := make(chan types.LookupFromResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "fdot")
	vch, ech := p.u.LoadPrefixKeys(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			parts := split(v.Key)
			dh := FromB64(parts[len(parts)-1])
			ds, err := p.loadDotState(ctx, dh)
			if err != nil {
				rv <- types.LookupFromResult{
					Err: err,
				}
				close(rv)
				return
			}

			//TODO filter dot by filter
			if filter.Valid != nil {
				if *filter.Valid {
					if ds.State != StateActive {

						continue
					}
				} else {
					if ds.State == StateActive {
						continue
					}
					//If we are here, the forward link existed, so it USED to be active
					//but has since expired or been revoked, presumably thats what the
					//caller is looking for
				}
			}
			if filter.GlobalNS != nil && *filter.GlobalNS {
				//Only return dots with a global namespace
				if len(ds.Dot.Content.NS) != 0 {
					continue
				}
			} else if filter.Namespace != nil {
				//Filter only a specific namespace (or global)
				if len(ds.Dot.Content.NS) != 0 && !bytes.Equal(ds.Dot.Content.NS, filter.Namespace) {
					continue
				}
			}
			lfr := types.LookupFromResult{
				Dot: ds.Dot,
			}
			select {
			case rv <- lfr:
			case <-ctx.Done():
				rv <- types.LookupFromResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- types.LookupFromResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}
