package engine

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
	localdb "github.com/immesys/wave/localdb/types"
	"github.com/immesys/wave/storage"
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
	//"*" for global
	Namespace *string
}

type LookupResult struct {
	//The dot but also its validity
	DOT      *dot.DOT
	Validity *Validity
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
func (e *Engine) LookupDOTSFrom(ctx context.Context, entityHash []byte, filter *Filter) (chan *LookupResult, chan error) {
	//The external context does not have our perspective, but we want it so the caller
	//can cancel
	subctx, cancel := context.WithCancel(context.WithValue(ctx, PerspectiveKey, e.perspective))
	lff := localdb.LookupFromFilter(*filter)
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
		for res := range e.ws.GetActiveDotsFromP(subctx, entityHash, &lff) {
			if subctx.Err() != nil {
				return fin(subctx.Err())
			}
			if res.Err != nil {
				return fin(res.Err)
			}
			validity, err := e.CheckDot(subctx, res.Dot)
			if err != nil {
				return fin(err)
			}
			select {
			case rv <- &LookupResult{
				DOT:      res.Dot,
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
	WaitSyncEmpty       chan struct{}
	CurrentBlock        int64
	CurrentTime         int64
	TotalSyncRequests   int64
	TotalCompletedSyncs int64
}

func (e *Engine) SyncStatus(ctx context.Context) (*SyncStatus, error) {
	si, err := e.st.GetStateInformation(ctx)
	if err != nil {
		return nil, err
	}
	e.totalMutex.Lock()
	sq := e.totalEqual
	e.totalMutex.Unlock()
	return &SyncStatus{
		WaitSyncEmpty:       sq,
		CurrentBlock:        si.CurrentBlock,
		CurrentTime:         si.CurrentTime,
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
func (e *Engine) LookupDotNoPerspective(ctx context.Context, hash []byte, aesk []byte, location storage.Location) (*dot.DOT, *Validity, error) {
	if len(aesk) != dot.AESKeyholeSize {
		return nil, nil, fmt.Errorf("invalid AES Keyhole parameter")
	}
	dotreg, _, err := e.st.RetrieveDOTByHash(ctx, hash, location)
	if err != nil {
		return nil, nil, err
	}
	if dotreg == nil {
		return nil, nil, nil
	}
	//decode it using aesk
	dctx := NewEngineDecryptionContext(e, nil)
	dres, err := dot.DecryptDOTWithAESK(ctx, dotreg.Data, aesk, dctx)
	if err != nil {
		return nil, nil, err
	}
	if dres.BadOrMalformed {
		return nil, &Validity{
			Valid:     false,
			Malformed: true,
		}, nil
	}
	validity, err := e.CheckDot(ctx, dres.DOT)
	if err != nil {
		return nil, nil, err
	}
	return dres.DOT, validity, nil
}

func (e *Engine) LookupDotInPerspective(ctx context.Context, hash []byte) (*dot.DOT, *Validity, error) {
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
func (e *Engine) CheckDot(ctx context.Context, d *dot.DOT) (*Validity, error) {
	srcokay, err := e.CheckEntity(ctx, d.SRC)
	if err != nil {
		return nil, err
	}
	dstokay, err := e.CheckEntity(ctx, d.DST)
	if err != nil {
		return nil, err
	}
	expired, err := d.Expired()
	if err != nil {
		return nil, err
	}
	revoked, err := e.IsRevoked(e.ctx, d.PlaintextHeader.RevocationHash)
	if err != nil {
		return nil, err
	}

	if !srcokay.Valid {
		return &Validity{
			Valid:      false,
			SrcInvalid: true,
		}, nil
	}
	if !dstokay.Valid {
		return &Validity{
			Valid:      false,
			DstInvalid: true,
		}, nil
	}

	if revoked {
		return &Validity{
			Valid:   false,
			Revoked: true,
		}, nil
	}
	if expired {
		return &Validity{
			Valid:   false,
			Expired: true,
		}, nil
	}
	return &Validity{Valid: true}, nil
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
