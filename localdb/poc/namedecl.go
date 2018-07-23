package poc

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/immesys/wave/iapi"
)

func (p *poc) saveNameDeclState(ctx context.Context, ds *NameDeclarationState) error {
	k := p.PKey(ctx, "ndcl", ToB64(ds.Hash))
	if ds.Hash == nil {
		panic("need hash")
	}
	ba, err := marshalGob(ds)
	if err != nil {
		return err
	}
	return p.u.Store(ctx, k, ba)
}
func (p *poc) loadNameDeclState(ctx context.Context, hash []byte) (*NameDeclarationState, error) {
	k := p.PKey(ctx, "ndcl", ToB64(hash))
	ba, err := p.u.Load(ctx, k)
	if err != nil {
		return nil, err
	}
	if ba == nil {
		return nil, nil
	}
	ds := &NameDeclarationState{}
	err = unmarshalGob(ba, ds)
	if err != nil {
		panic(err)
	}
	return ds, nil
}

func (p *poc) setNameDeclStateField(ctx context.Context, dh []byte, state int) error {
	ds, err := p.loadNameDeclState(ctx, dh)
	if err != nil {
		return err
	}
	if ds == nil {
		//We don't care anyway
		return nil
	}
	ds.State = state
	return p.saveNameDeclState(ctx, ds)
}

func keccakFromND(nd *iapi.NameDeclaration) []byte {
	hsh := nd.Hash(iapi.KECCAK256)
	val := hsh.Value()
	return val
}

func (p *poc) MoveNameDeclarationPendingP(ctx context.Context, nd *iapi.NameDeclaration, labelKeyIndex int) error {
	hash := keccakFromND(nd)
	ds, err := p.loadNameDeclState(ctx, hash)
	if err != nil {
		return err
	}
	if ds != nil {
		panic("we moved a name declaration into pending when we already knew about it?")
	}
	ds = &NameDeclarationState{
		State:           StatePending,
		Hash:            hash,
		NameDeclaration: nd,
		LabelKeyIndex:   labelKeyIndex,
	}
	return p.saveNameDeclState(ctx, ds)
}

func (p *poc) UpdateNameDeclarationPendingP(ctx context.Context, nd *iapi.NameDeclaration, labelKeyIndex int) error {
	hash := keccakFromND(nd)
	if nd.WR1Extra == nil {
		panic("pending ND with no WR1?")
	}
	ds, err := p.loadNameDeclState(ctx, hash)
	if err != nil {
		return err
	}
	if ds == nil {
		panic("trying to update lki on nonexistent namedecl")
	}
	if ds.State != StatePending {
		panic("trying to update lki on namedecl not pending")
	}
	if labelKeyIndex <= ds.LabelKeyIndex {
		panic("label key index is LTE the current one")
	}
	ds.LabelKeyIndex = labelKeyIndex
	return p.saveNameDeclState(ctx, ds)
}

func (p *poc) MoveNameDeclarationLabelledP(ctx context.Context, nd *iapi.NameDeclaration) error {
	if nd.WR1Extra == nil {
		panic("how are we here")
	}
	nshash := keccakFromHI(nd.WR1Extra.Namespace)
	err := p.insertPartitionToNameDeclLink(ctx, nshash, nd.WR1Extra.Partition, nd)
	if err != nil {
		return err
	}
	ds := &NameDeclarationState{
		State:           StateLabelled,
		NameDeclaration: nd,
		Hash:            keccakFromND(nd),
	}
	return p.saveNameDeclState(ctx, ds)
}

func (p *poc) MoveNameDeclarationActiveP(ctx context.Context, nd *iapi.NameDeclaration) error {
	hsh := keccakFromND(nd)
	//If nd has real info, remove the active link in case it exists
	if nd.DecryptedBody == nil {
		panic("active but no nd body?")
	}
	name := nd.DecryptedBody.Name
	createDate := nd.DecryptedBody.Validity.NotBefore.UnixNano()
	attester := keccakFromHI(nd.Attester)
	err := p.insertNDActiveLink(ctx, attester, name, createDate, hsh)
	if err != nil {
		return err
	}
	ds := &NameDeclarationState{
		State:           StateActive,
		NameDeclaration: nd,
		Hash:            hsh,
	}
	return p.saveNameDeclState(ctx, ds)
}

//For the next three functions, the next time we call a resolve function, the resolve index
//will see the state change and update the index
func (p *poc) MoveNameDeclarationExpiredP(ctx context.Context, nd *iapi.NameDeclaration) error {
	hsh := keccakFromND(nd)
	//If nd has real info, remove the active link in case it exists
	if nd.DecryptedBody != nil {
		name := nd.DecryptedBody.Name
		createDate := nd.DecryptedBody.Validity.NotBefore.UnixNano()
		attester := keccakFromHI(nd.Attester)
		err := p.removeNDActiveLink(ctx, attester, name, createDate, hsh)
		if err != nil {
			return err
		}
	}
	return p.setNameDeclStateField(ctx, hsh, StateExpired)
}

func (p *poc) MoveNameDeclarationRevokedP(ctx context.Context, nd *iapi.NameDeclaration) error {
	hsh := keccakFromND(nd)
	//If nd has real info, remove the active link in case it exists
	if nd.DecryptedBody != nil {
		name := nd.DecryptedBody.Name
		createDate := nd.DecryptedBody.Validity.NotBefore.UnixNano()
		attester := keccakFromHI(nd.Attester)
		err := p.removeNDActiveLink(ctx, attester, name, createDate, hsh)
		if err != nil {
			return err
		}
	}
	return p.setNameDeclStateField(ctx, hsh, StateRevoked)
}

func (p *poc) MoveNameDeclarationMalformedP(ctx context.Context, hsi iapi.HashSchemeInstance) error {
	return p.setNameDeclStateField(ctx, hsi.Value(), StateMalformed)
}

func (p *poc) GetLabelledNameDeclarationsP(pctx context.Context, nshi iapi.HashSchemeInstance, partition [][]byte) chan iapi.PendingNameDeclaration {
	ns := keccakFromHI(nshi)
	rv := make(chan iapi.PendingNameDeclaration, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "ndl", ToB64(ns))
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {

			pl := &PendingLabels{}
			err := unmarshalGob(v.Value, pl)
			if err != nil {
				panic(err)
			}
			//Only return this nd if the given partition is a superset
			//of the dot
			if !matchPartition(partition, pl.Slots) {
				continue
			}

			parts := split(v.Key)
			dh := FromB64(parts[len(parts)-1])
			ds, err := p.loadNameDeclState(ctx, dh)
			if err != nil {
				rv <- iapi.PendingNameDeclaration{
					Err: err,
				}
				close(rv)
				return
			}
			pdr := iapi.PendingNameDeclaration{
				NameDeclaration: ds.NameDeclaration,
				Keccak256:       ds.Hash,
				LabelKeyIndex:   &ds.LabelKeyIndex,
			}
			select {
			case rv <- pdr:
			case <-ctx.Done():
				rv <- iapi.PendingNameDeclaration{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.PendingNameDeclaration{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) GetPendingNameDeclarationP(pctx context.Context, nshi iapi.HashSchemeInstance, lkiLT int) chan iapi.PendingNameDeclaration {
	ns := keccakFromHI(nshi)
	//TODO I don't think we do this properly, we are scanning too many nds here
	//we should only scan those with a ns that matches
	rv := make(chan iapi.PendingNameDeclaration, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "ndcl")
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			ds := &NameDeclarationState{}
			err := unmarshalGob(v.Value, ds)
			if err != nil {
				panic(err)
			}
			if ds.State != StatePending {
				continue
			}
			recns := keccakFromHI(ds.NameDeclaration.WR1Extra.Namespace)
			if !bytes.Equal(recns, ns) {
				continue
			}
			if lkiLT >= 0 && ds.LabelKeyIndex >= lkiLT {
				continue
			}
			pdr := iapi.PendingNameDeclaration{
				NameDeclaration: ds.NameDeclaration,
				Keccak256:       ds.Hash,
				LabelKeyIndex:   &ds.LabelKeyIndex,
			}

			select {
			case rv <- pdr:
			case <-ctx.Done():
				rv <- iapi.PendingNameDeclaration{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.PendingNameDeclaration{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) insertNDActiveLink(ctx context.Context, attester []byte, name string, createDate int64, ndhash []byte) error {
	k := p.PKey(ctx, "ndal", ToB64(attester), name, fmt.Sprintf("%016d", createDate), ToB64(ndhash))
	return p.u.Store(ctx, k, []byte{1})
}
func (p *poc) removeNDActiveLink(ctx context.Context, attester []byte, name string, createDate int64, ndhash []byte) error {
	k := p.PKey(ctx, "ndal", ToB64(attester), name, fmt.Sprintf("%016d", createDate), ToB64(ndhash))
	return p.u.Remove(ctx, k)
}

func (p *poc) ResolveNameDeclarationsP(pctx context.Context, attester iapi.HashSchemeInstance, name string) chan iapi.ResolveResult {
	k := p.PKey(pctx, "ndal", ToB64(keccakFromHI(attester)), name)
	rv := make(chan iapi.ResolveResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	vch, ech := p.u.LoadPrefixKeys(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			parts := strings.Split(v.Key, "/")
			ndhash := FromB64(parts[len(parts)-1])
			rr, err := p.loadNameDeclState(ctx, ndhash)
			if err != nil {
				rv <- iapi.ResolveResult{
					Err: err,
				}
				close(rv)
				return
			}
			pdr := iapi.ResolveResult{
				NameDeclaration: rr.NameDeclaration,
			}
			select {
			case rv <- pdr:
			case <-ctx.Done():
				rv <- iapi.ResolveResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.ResolveResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}
