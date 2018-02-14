package poc

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/localdb/types"
	dot "github.com/immesys/wave/olddot"
	"github.com/immesys/wave/params"
)

func (p *poc) getPartitionLabelKeyP(ctx context.Context, dst []byte, index int) (*PLKState, error) {
	k := p.PKey(ctx, "plk", ToB64(dst), fmt.Sprintf("%06d", index))
	ba, err := p.u.Load(ctx, k)
	if err != nil {
		return nil, err
	}
	if ba == nil {
		return nil, nil
	}
	plks := &PLKState{}
	err = unmarshalGob(ba, plks)
	if err != nil {
		panic(err)
	}
	return plks, nil
}
func (p *poc) GetPartitionLabelKeyP(ctx context.Context, dst []byte, index int) (*types.Secret, error) {
	plks, err := p.getPartitionLabelKeyP(ctx, dst, index)
	if err != nil {
		return nil, err
	}
	return &types.Secret{
		Slots: plks.Slots,
		Key:   plks.Key,
	}, nil
}

func nsToSlots(ns []byte) [][]byte {
	rv := make([][]byte, params.OAQUESlots)
	rv[0] = []byte(dot.OAQUEMetaSlotPartitionLabel)
	if len(ns) > 0 {
		rv[1] = ns
	} else {
		rv[1] = []byte("*")
	}
	return rv
}

//TODO some kind of mutex on the entity PLKS ? we have a bit of a race here with the index
func (p *poc) InsertPartitionLabelKeyP(ctx context.Context, ent []byte, namespace []byte, key *oaque.PrivateKey) (new bool, err error) {
	es, err := p.loadEntity(ctx, ent)
	if err != nil {
		return false, err
	}
	//Scan through all PLKs to check if this one is new
	for i := 0; i < es.MaxLabelKeyIndex; i++ {
		plks, err := p.getPartitionLabelKeyP(ctx, ent, i)
		if err != nil {
			return false, err
		}
		if bytes.Equal(plks.Namespace, namespace) {
			//We have this key already
			return false, nil
		}
	}
	//New key
	k := p.PKey(ctx, "plk", ToB64(ent), fmt.Sprintf("%06d", es.MaxLabelKeyIndex))
	nplks := &PLKState{
		Slots: nsToSlots(namespace),
		Key:   key,
	}
	ba, err := nplks.MarshalMsg(nil)
	if err != nil {
		panic(err)
	}
	err = p.u.Store(ctx, k, ba)
	if err != nil {
		return false, nil
	}
	es.MaxLabelKeyIndex++
	return true, p.saveEntityState(ctx, es)
}

//This is to facilitate GetLAbelledDotsP. Gets called when moving dots to labelled
func (p *poc) insertPartitionToDotLink(ctx context.Context, dst []byte, partition [][]byte, dt *dot.DOT) error {
	k := p.PKey(ctx, "pdl", ToB64(dst), ToB64(dt.Hash))
	pl := &PendingLabels{Slots: partition}
	ba, err := pl.MarshalMsg(nil)
	if err != nil {
		panic(err)
	}
	return p.u.Store(ctx, k, ba)
}

//In this case we want dots that are MORE qualified than the given partition
func (p *poc) GetLabelledDotsP(pctx context.Context, dst []byte, partition [][]byte) chan types.PendingDOTResult {
	rv := make(chan types.PendingDOTResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "pdl", ToB64(dst))
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {

			pl := &PendingLabels{}
			_, err := pl.UnmarshalMsg(v.Value)
			if err != nil {
				panic(err)
			}
			//Only return this dot if the given partition is a superset
			//of the dot
			if !matchPartition(partition, pl.Slots) {
				continue
			}

			parts := split(v.Key)
			dh := FromB64(parts[len(parts)-1])
			ds, err := p.loadDotState(ctx, dh)
			if err != nil {
				rv <- types.PendingDOTResult{
					Err: err,
				}
				close(rv)
				return
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

func matchPartition(superset [][]byte, subset [][]byte) bool {
	if len(superset) != len(subset) {
		panic("slots not the same length")
	}
	for idx, super := range superset {
		if len(super) == 0 {
			continue
		}
		if bytes.Equal(super, subset[idx]) {
			continue
		}
		return false
	}
	return true
}

func (p *poc) OAQUEKeysForP(ctx context.Context, dst []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	k := p.PKey(ctx, "oaq", ToB64(dst))
	vch, ech := p.u.LoadPrefix(ctx, k)
	for v := range vch {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		cks := &ContentKeyState{}
		_, err := cks.UnmarshalMsg(v.Value)
		if err != nil {
			panic(err)
		}

		pl := &PendingLabels{}
		_, err = pl.UnmarshalMsg(v.Value)
		if err != nil {
			panic(err)
		}
		//Only return this dot if the given partition is a superset
		//of the dot
		if !matchPartition(cks.Slots, slots) {
			continue
		}

		//The key is a superset of the given slots
		more := onResult(cks.Key)
		if !more {
			return nil
		}
	}
	return <-ech
}
func (p *poc) InsertOAQUEKeysForP(ctx context.Context, from []byte, slots [][]byte, key *oaque.PrivateKey) error {
	bslots := make([]string, len(slots))
	for i, s := range slots {
		bslots[i] = ToB64(s)
	}
	allSlots := strings.Join(bslots, "/")
	k := p.PKey(ctx, "oaq", ToB64(from), allSlots)
	cks := &ContentKeyState{
		Slots: slots,
		Key:   key,
	}
	ba, err := cks.MarshalMsg(nil)
	if err != nil {
		panic(err)
	}
	return p.u.Store(ctx, k, ba)

}
