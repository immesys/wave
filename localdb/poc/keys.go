package poc

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/immesys/wave/iapi"
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
func (p *poc) GetPartitionLabelKeyP(ctx context.Context, dsthi iapi.HashSchemeInstance, index int) (iapi.EntitySecretKeySchemeInstance, error) {
	dst := keccakFromHI(dsthi)
	plks, err := p.getPartitionLabelKeyP(ctx, dst, index)
	if err != nil {
		return nil, err
	}
	return plks.Key, nil
}

/*
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
*/

//TODO some kind of mutex on the entity PLKS ? we have a bit of a race here with the index
func (p *poc) InsertPartitionLabelKeyP(ctx context.Context, ent iapi.HashSchemeInstance, key iapi.EntitySecretKeySchemeInstance) (new bool, err error) {
	ehash := keccakFromHI(ent)
	es, err := p.loadEntity(ctx, ehash)
	if err != nil {
		return false, err
	}
	//Scan through all PLKs to check if this one is new
	for i := 0; i < es.MaxLabelKeyIndex; i++ {
		plks, err := p.getPartitionLabelKeyP(ctx, ehash, i)
		if err != nil {
			return false, err
		}
		if plks.Key.Equal(key) {
			//We have this key already
			return false, nil
		}
	}
	//New key
	k := p.PKey(ctx, "plk", ToB64(ehash), fmt.Sprintf("%06d", es.MaxLabelKeyIndex))
	nplks := &PLKState{
		Key: key,
	}
	ba, err := marshalGob(nplks)
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
func (p *poc) insertPartitionToAttestationLink(ctx context.Context, dst []byte, partition [][]byte, dt *iapi.Attestation) error {
	k := p.PKey(ctx, "pdl", ToB64(dst), ToB64(keccakFromAtt(dt)))
	pl := &PendingLabels{Slots: partition}
	ba, err := marshalGob(pl)
	if err != nil {
		panic(err)
	}
	return p.u.Store(ctx, k, ba)
}

//In this case we want dots that are MORE qualified than the given partition
func (p *poc) GetLabelledAttestationsP(pctx context.Context, dsthi iapi.HashSchemeInstance, partition [][]byte) chan iapi.PendingAttestation {
	dst := keccakFromHI(dsthi)
	rv := make(chan iapi.PendingAttestation, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "pdl", ToB64(dst))
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {

			pl := &PendingLabels{}
			err := unmarshalGob(v.Value, pl)
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
			ds, err := p.loadAttestationState(ctx, dh)
			if err != nil {
				rv <- iapi.PendingAttestation{
					Err: err,
				}
				close(rv)
				return
			}
			pdr := iapi.PendingAttestation{
				Attestation:   ds.Attestation,
				Keccak256:     ds.Hash,
				LabelKeyIndex: &ds.LabelKeyIndex,
			}
			select {
			case rv <- pdr:
			case <-ctx.Done():
				rv <- iapi.PendingAttestation{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.PendingAttestation{
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

func (p *poc) WR1KeysForP(ctx context.Context, dsthi iapi.HashSchemeInstance, slots [][]byte, onResult func(k iapi.SlottedSecretKey) bool) error {
	dst := keccakFromHI(dsthi)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	k := p.PKey(ctx, "oaq", ToB64(dst))
	vch, ech := p.u.LoadPrefix(ctx, k)
	for v := range vch {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		cks := &ContentKeyState{}
		err := unmarshalGob(v.Value, cks)
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
func (p *poc) InsertWR1KeysForP(ctx context.Context, fromhi iapi.HashSchemeInstance, key iapi.SlottedSecretKey) error {
	from := keccakFromHI(fromhi)
	slots := key.Slots()
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
	ba, err := marshalGob(cks)
	if err != nil {
		panic(err)
	}
	return p.u.Store(ctx, k, ba)

}
