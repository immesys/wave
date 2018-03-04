package engine

import (
	"context"
	"sync/atomic"

	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/iapi"
)

//functions that the engine needs from above

//TODO everything needs to be parameterized by "view" which is the controlling entity
//functions that others use from the engine

//actions that can happen:
//automated
/*
new block:
  events suggesting VKs have new entries
  events suggesting new entities
received proof (learned):
  decoded dots
*/
//user triggered
/*
new dot:
  e.g. from out of band
entity becomes interesting


*/
// new block arrives:

type Validity struct {
	//Like if revoked / expired / entExpired etc
	//shared between entity and dot
	Valid     bool
	Revoked   bool
	Expired   bool
	Malformed bool
	//Only for dots
	SrcInvalid bool
	DstInvalid bool
}

type Filter struct {
	//Like namespace and permissions and stuff
	//backend might be able to index some of it
	//also validity
	Valid *bool
}

type LookupResult struct {
	//The dot but also its validity
	Attestation *iapi.Attestation
	Validity    *Validity
}

// received proof:

// TODO formulate dots decoded with AESK
// TODO how to decrypt a dot that you granted yourself?

//External function: insert a DOT learned out of band
func (e *Engine) InsertDOT(ctx context.Context, encodedDOT []byte) error {
	//this must go into pending even if decryptable
	//to avoid racing with the labelled->active stuff
	return e.insertPendingDotBlob(encodedDOT, true)
}

//External function: get dots granted from an entity on a namespace.
//global grants will also be returned. The returned channel must be consumed
//completely, or the context must be cancelled
func (e *Engine) LookupAttestationsFrom(ctx context.Context, entityHash iapi.HashSchemeInstance, filter *iapi.LookupFromFilter) (chan *LookupResult, chan error) {
	//The external context does not have our perspective, but we want it so the caller
	//can cancel
	subctx, cancel := context.WithCancel(context.WithValue(ctx, PerspectiveKey, e.perspective))
	rv := make(chan *LookupResult, 10)
	rve := make(chan error, 1)
	go func() error {
		defer cancel()
		fin := func(e error) error {
			rve <- e
			close(rv)
			close(rve)
			return e
		}
		for res := range e.ws.GetActiveAttestationsFromP(subctx, entityHash, filter) {
			if subctx.Err() != nil {
				return fin(subctx.Err())
			}
			if res.Err != nil {
				return fin(res.Err)
			}
			validity, err := e.CheckAttestation(subctx, res.Attestation)
			if err != nil {
				return fin(err)
			}
			select {
			case rv <- &iapi.LookupFromResult{
				Attestation:
				Validity: validity,
			}:
			case <-subctx.Done():
				return fin(subctx.Err())
			}
		}
		return fin(nil)
	}()
	return rv, rve
}

type SyncStatus struct {
	WaitSyncEmpty chan struct{}
	// CurrentBlock        int64
	// CurrentTime         int64
	TotalSyncRequests   int64
	TotalCompletedSyncs int64
}

func (e *Engine) SyncStatus(ctx context.Context) (*SyncStatus, error) {
	// si, err := e.st.GetStateInformation(ctx)
	// if err != nil {
	// 	return nil, err
	// }
	e.totalMutex.Lock()
	sq := e.totalEqual
	e.totalMutex.Unlock()
	return &SyncStatus{
		WaitSyncEmpty: sq,
		// CurrentBlock:        si.CurrentBlock,
		// CurrentTime:         si.CurrentTime,
		TotalSyncRequests:   atomic.LoadInt64(&e.totalSyncRequests),
		TotalCompletedSyncs: atomic.LoadInt64(&e.totalCompletedSyncs),
	}, nil
}

//The returned channel will be closed the next time the sync queue is empty
func (e *Engine) WaitForEmptySyncQueue() chan struct{} {
	e.totalMutex.Lock()
	rv := e.totalEqual
	e.totalMutex.Unlock()
	return rv
}

//We should have a function that allows applications to tap into perspective changes
//for the purposes of alerts and so on (also avoiding polling)
func (e *Engine) SubscribePerspectiveChanges(ctx context.Context, someAdditionStuff string) {
	panic("ni")
}

//For things like brokers, they will want to subscribe to changes on dots and
//entities used in active subscriptions, rather than polling
func (e *Engine) SubscribeRevocations(ctx context.Context, interesting [][]byte) {
	panic("ni")
}

//This should try find and decrypt a dot given the hash and aesk. No information from our
//perspective (active entity) is used
func (e *Engine) LookupAttestationNoPerspective(ctx context.Context, hash []byte, k iapi.AttestationVerifierKeySchemeInstance, location iapi.LocationSchemeInstance) (*iapi.Attestation, *Validity, error) {

	//REFACTOR if len(aesk) != dot.AESKeyholeSize {
	//REFACTOR 	return nil, nil, fmt.Errorf("invalid AES Keyhole parameter")
	//REFACTOR }
	//REFACTOR dotreg, _, err := e.st.RetrieveDOTByHash(ctx, hash, location)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, nil, err
	//REFACTOR }
	//REFACTOR if dotreg == nil {
	//REFACTOR 	return nil, nil, nil
	//REFACTOR }
	//REFACTOR //decode it using aesk
	//REFACTOR dctx := NewEngineDecryptionContext(e, nil)
	//REFACTOR dres, err := dot.DecryptDOTWithAESK(ctx, dotreg.Data, aesk, dctx)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, nil, err
	//REFACTOR }
	//REFACTOR if dres.BadOrMalformed {
	//REFACTOR 	return nil, &Validity{
	//REFACTOR 		Valid:     false,
	//REFACTOR 		Malformed: true,
	//REFACTOR 	}, nil
	//REFACTOR }
	//REFACTOR validity, err := e.CheckDot(ctx, dres.DOT)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, nil, err
	//REFACTOR }
	//REFACTOR return dres.DOT, validity, nil
}

func (e *Engine) LookupDotInPerspective(ctx context.Context, hash []byte) (*iapi.Attestation, *Validity, error) {
	subctx := context.WithValue(ctx, PerspectiveKey, e.perspective)
	dot, err := e.ws.GetDotP(subctx, hash)
	if err != nil {
		return nil, nil, err
	}
	val, err := e.CheckDot(ctx, dot)
	if err != nil {
		return nil, nil, err
	}
	return dot, val, nil
}

//Unlike checkDot, this should not touch the DB, it is a read-only operation
func (e *Engine) CheckDot(ctx context.Context, d *iapi.Attestation) (*Validity, error) {
	panic("ni")
	//REFACTOR srcokay, err := e.CheckEntity(ctx, d.SRC)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, err
	//REFACTOR }
	//REFACTOR dstokay, err := e.CheckEntity(ctx, d.DST)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, err
	//REFACTOR }
	//REFACTOR expired, err := d.Expired()
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, err
	//REFACTOR }
	//REFACTOR revoked, err := e.IsRevoked(e.ctx, d.PlaintextHeader.RevocationHash)
	//REFACTOR if err != nil {
	//REFACTOR 	return nil, err
	//REFACTOR }

	//REFACTOR if !srcokay.Valid {
	//REFACTOR 	return &Validity{
	//REFACTOR 		Valid:      false,
	//REFACTOR 		SrcInvalid: true,
	//REFACTOR 	}, nil
	//REFACTOR }
	//REFACTOR if !dstokay.Valid {
	//REFACTOR 	return &Validity{
	//REFACTOR 		Valid:      false,
	//REFACTOR 		DstInvalid: true,
	//REFACTOR 	}, nil
	//REFACTOR }

	//REFACTOR if revoked {
	//REFACTOR 	return &Validity{
	//REFACTOR 		Valid:   false,
	//REFACTOR 		Revoked: true,
	//REFACTOR 	}, nil
	//REFACTOR }
	//REFACTOR if expired {
	//REFACTOR 	return &Validity{
	//REFACTOR 		Valid:   false,
	//REFACTOR 		Expired: true,
	//REFACTOR 	}, nil
	//REFACTOR }
	//REFACTOR return &Validity{Valid: true}, nil
}
func (e *Engine) CheckEntity(ctx context.Context, ent *entity.Entity) (*Validity, error) {
	if ent.Expired() {
		return &Validity{Valid: false, Expired: true}, nil
	}
	revoked, err := e.IsRevoked(e.ctx, ent.RevocationHash)
	if err != nil {
		return nil, err
	}
	if revoked {
		return &Validity{Valid: false, Revoked: true}, nil
	}
	return &Validity{Valid: true}, nil
}

func (e *Engine) LookupEntity(ctx context.Context, hash []byte) (*entity.Entity, *Validity, error) {
	//TODO this should do some caching
	reg, _, err := e.st.RetrieveEntity(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	if reg == nil {
		return nil, nil, nil
	}
	ent, err := entity.UnpackEntity(reg.Data)
	if err != nil {
		//NOT TRAGIC
		return nil, &Validity{Valid: false, Malformed: true}, nil
	}
	validity, err := e.CheckEntity(ctx, ent)
	if err != nil {
		return nil, nil, err
	}
	return ent, validity, nil
}

//TODO this function should do some caching
func (e *Engine) IsRevoked(ctx context.Context, hash []byte) (bool, error) {
	rvk, _, err := e.st.RetrieveRevocation(ctx, hash)
	if err != nil {
		return false, err
	}
	if rvk != nil {
		return true, nil
	}
	return false, nil
}
