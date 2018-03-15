package poc

import (
	"bytes"
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/asn1"
	"github.com/immesys/wave/iapi"
)

func keccakFromHI(h iapi.HashSchemeInstance) []byte {
	val := h.Value()

	return val
}
func keccakFromAtt(att *iapi.Attestation) []byte {
	hsh := att.Hash(iapi.KECCAK256)
	val := hsh.Value()
	return val
}
func keccakFromExt(e *asn1.External) []byte {
	hi := iapi.HashSchemeInstanceFor(e)
	_, ok := hi.(*iapi.HashSchemeInstance_Keccak_256)
	if !ok {
		spew.Dump(hi)
		panic("external is not keccak")
	}
	val := hi.Value()
	return val
}
func (p *poc) saveAttestationState(ctx context.Context, ds *AttestationState) error {
	k := p.PKey(ctx, "att", ToB64(ds.Hash))
	if ds.Hash == nil {
		panic("need hash")
	}
	ba, err := marshalGob(ds)
	if err != nil {
		return err
	}
	return p.u.Store(ctx, k, ba)
}
func (p *poc) loadAttestationState(ctx context.Context, hash []byte) (*AttestationState, error) {
	k := p.PKey(ctx, "att", ToB64(hash))
	ba, err := p.u.Load(ctx, k)
	if err != nil {
		return nil, err
	}
	if ba == nil {
		return nil, nil
	}
	ds := &AttestationState{}
	err = unmarshalGob(ba, ds)
	if err != nil {
		panic(err)
	}
	return ds, nil
}

func (p *poc) setAttestationStateField(ctx context.Context, dh []byte, state int) error {
	ds, err := p.loadAttestationState(ctx, dh)
	if err != nil {
		return err
	}
	if ds == nil {
		//We don't care anyway
		return nil
	}
	ds.State = state
	return p.saveAttestationState(ctx, ds)
}

//Note that we are treating this as a P function here, but it doesn't
//really matter
func (p *poc) MoveAttestationRevokedG(ctx context.Context, att *iapi.Attestation) error {
	hsh := keccakFromAtt(att)
	return p.setAttestationStateField(ctx, hsh, StateRevoked)
}
func (p *poc) GetAttestationP(ctx context.Context, hi iapi.HashSchemeInstance) (d *iapi.Attestation, err error) {
	hsh := keccakFromHI(hi)
	ds, err := p.loadAttestationState(ctx, hsh)
	if err != nil {
		return nil, err
	}
	if ds == nil {
		//We don't care anyway
		return nil, nil
	}

	return ds.Attestation, nil
}
func (p *poc) MoveAttestationMalformedP(ctx context.Context, hi iapi.HashSchemeInstance) error {
	hash := keccakFromHI(hi)
	return p.setAttestationStateField(ctx, hash, StateMalformed)
}
func (p *poc) MoveAttestationExpiredP(ctx context.Context, att *iapi.Attestation) error {
	hash := keccakFromAtt(att)
	return p.setAttestationStateField(ctx, hash, StateExpired)
}
func (p *poc) MoveAttestationEntRevokedP(ctx context.Context, att *iapi.Attestation) error {
	hash := keccakFromAtt(att)
	return p.setAttestationStateField(ctx, hash, StateEntRevoked)
}

//
// func (p *poc) GetInterestingByRevocationHashP(pctx context.Context, rvkhash []byte) chan types.ReverseLookupResult {
// 	rv := make(chan types.ReverseLookupResult, 10)
// 	ctx, cancel := context.WithCancel(pctx)
// 	k := p.PKey(ctx, "rvk")
// 	vch, ech := p.u.LoadPrefix(ctx, k)
// 	go func() {
// 		defer cancel()
// 		for v := range vch {
// 			rs := &RevocationState{}
// 			_, err := rs.UnmarshalMsg(v.Value)
// 			if err != nil {
// 				panic(err)
// 			}
// 			rlr := types.ReverseLookupResult{
// 				Hash:  rs.TargetHash,
// 				IsDOT: !rs.IsEntity,
// 			}
// 			if rs.IsEntity {
// 				ent, err := p.loadEntity(ctx, rs.TargetHash)
// 				if err != nil {
// 					panic(err)
// 				}
// 				if ent == nil {
// 					panic("expected to find this")
// 				}
// 				rlr.Entity = ent.Entity
// 			} else {
// 				dot, err := p.loadDotState(ctx, rs.TargetHash)
// 				if err != nil {
// 					panic(err)
// 				}
// 				if dot == nil {
// 					panic("expected to find this")
// 				}
// 				rlr.Dot = dot.Dot
// 			}
// 			select {
// 			case rv <- rlr:
// 			case <-ctx.Done():
// 				rv <- types.ReverseLookupResult{
// 					Err: ctx.Err(),
// 				}
// 				close(rv)
// 				return
// 			}
// 		}
// 		err := <-ech
// 		if err != nil {
// 			rv <- types.ReverseLookupResult{
// 				Err: err,
// 			}
// 		}
// 		close(rv)
// 		return
// 	}()
// 	return rv
// }

func (p *poc) MoveAttestationPendingP(ctx context.Context, att *iapi.Attestation, labelKeyIndex int) error {
	hash := keccakFromAtt(att)
	ds, err := p.loadAttestationState(ctx, hash)
	if err != nil {
		return err
	}
	if ds != nil {
		panic("we moved a dot into pending when we already knew about it?")
	}
	ds = &AttestationState{
		State:         StatePending,
		Hash:          hash,
		Attestation:   att,
		LabelKeyIndex: labelKeyIndex,
	}
	return p.saveAttestationState(ctx, ds)
}
func (p *poc) UpdateAttestationPendingP(ctx context.Context, att *iapi.Attestation, labelKeyIndex int) error {
	hash := keccakFromAtt(att)
	ds, err := p.loadAttestationState(ctx, hash)
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
	return p.saveAttestationState(ctx, ds)
}
func (p *poc) GetPendingAttestationsP(pctx context.Context, dsthi iapi.HashSchemeInstance, lkiLT int) chan iapi.PendingAttestation {
	dsthash := keccakFromHI(dsthi)
	//TODO I don't think we do this properly, we are scanning too many dots here
	//we should only scan those with a DST that matches
	rv := make(chan iapi.PendingAttestation, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "att")
	vch, ech := p.u.LoadPrefix(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			ds := &AttestationState{}
			err := unmarshalGob(v.Value, ds)
			if err != nil {
				panic(err)
			}
			if ds.State != StatePending {
				continue
			}
			dst := keccakFromExt(&ds.Attestation.CanonicalForm.TBS.Subject)
			if !bytes.Equal(dst, dsthash) {
				continue
			}
			if lkiLT >= 0 && ds.LabelKeyIndex >= lkiLT {
				continue
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

func (p *poc) MoveAttestationLabelledP(ctx context.Context, att *iapi.Attestation) error {
	dsthash := keccakFromExt(&att.CanonicalForm.TBS.Subject)
	if att.WR1Extra == nil {
		panic("how are we here")
	}
	err := p.insertPartitionToAttestationLink(ctx, dsthash, att.WR1Extra.Partition, att)
	if err != nil {
		return err
	}
	ds := &AttestationState{
		State:       StateLabelled,
		Attestation: att,
		Hash:        keccakFromAtt(att),
	}
	return p.saveAttestationState(ctx, ds)
}
func (p *poc) insertActiveAttestationForwardLink(ctx context.Context, att *iapi.Attestation) error {
	srchash := keccakFromExt(&att.DecryptedBody.VerifierBody.Attester)
	k := p.PKey(ctx, "fdot", ToB64(srchash), ToB64(att.Keccak256()))
	//We don't really need a value
	return p.u.Store(ctx, k, []byte{1})
}
func (p *poc) insertActiveAttestationBackwardLink(ctx context.Context, att *iapi.Attestation) error {
	dsthash := keccakFromExt(&att.CanonicalForm.TBS.Subject)
	k := p.PKey(ctx, "bdot", ToB64(dsthash), ToB64(att.Keccak256()))
	//We don't really need a value
	return p.u.Store(ctx, k, []byte{1})
}
func (p *poc) MoveAttestationActiveP(ctx context.Context, att *iapi.Attestation) error {
	err := p.insertActiveAttestationForwardLink(ctx, att)
	if err != nil {
		return err
	}
	err = p.insertActiveAttestationBackwardLink(ctx, att)
	if err != nil {
		return err
	}
	ds := &AttestationState{
		State:       StateActive,
		Hash:        keccakFromAtt(att),
		Attestation: att,
	}
	return p.saveAttestationState(ctx, ds)
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
func (p *poc) GetActiveAttestationsFromP(pctx context.Context, srchi iapi.HashSchemeInstance, filter *iapi.LookupFromFilter) chan iapi.LookupFromResult {
	src := keccakFromHI(srchi)
	rv := make(chan iapi.LookupFromResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "fdot", ToB64(src))
	vch, ech := p.u.LoadPrefixKeys(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			parts := split(v.Key)
			// srch := FromB64(parts[len(parts)-2])
			// if !bytes.Equal(src, srch) {
			// 	continue
			// }
			dh := FromB64(parts[len(parts)-1])
			ds, err := p.loadAttestationState(ctx, dh)
			if err != nil {
				rv <- iapi.LookupFromResult{
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
			//TODO
			/*
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
			*/
			lfr := iapi.LookupFromResult{
				Attestation: ds.Attestation,
			}
			select {
			case rv <- lfr:
			case <-ctx.Done():
				rv <- iapi.LookupFromResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.LookupFromResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}

func (p *poc) GetActiveAttestationsToP(pctx context.Context, dsthi iapi.HashSchemeInstance, filter *iapi.LookupFromFilter) chan iapi.LookupFromResult {
	dst := keccakFromHI(dsthi)
	rv := make(chan iapi.LookupFromResult, 10)
	ctx, cancel := context.WithCancel(pctx)
	k := p.PKey(ctx, "bdot", ToB64(dst))
	vch, ech := p.u.LoadPrefixKeys(ctx, k)
	go func() {
		defer cancel()
		for v := range vch {
			parts := split(v.Key)
			dh := FromB64(parts[len(parts)-1])
			ds, err := p.loadAttestationState(ctx, dh)
			if err != nil {
				rv <- iapi.LookupFromResult{
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
			lfr := iapi.LookupFromResult{
				Attestation: ds.Attestation,
			}
			select {
			case rv <- lfr:
			case <-ctx.Done():
				rv <- iapi.LookupFromResult{
					Err: ctx.Err(),
				}
				close(rv)
				return
			}
		}
		err := <-ech
		if err != nil {
			rv <- iapi.LookupFromResult{
				Err: err,
			}
		}
		close(rv)
		return
	}()
	return rv
}
