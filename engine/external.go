package engine

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/immesys/wave/consts"
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
	Valid        bool
	Revoked      bool
	Expired      bool
	Malformed    bool
	NotDecrypted bool

	//Only for dots
	SrcInvalid bool
	DstInvalid bool

	Message string
}

type Filter struct {
	//Like namespace and permissions and stuff
	//backend might be able to index some of it
	//also validity
	Valid *bool
}

type LookupResult struct {
	//The dot but also its validity
	Attestation    *iapi.Attestation
	KnownLocations []iapi.LocationSchemeInstance
	Validity       *Validity
}

// received proof:

// TODO formulate dots decoded with AESK
// TODO how to decrypt a dot that you granted yourself?
// func (e *Engine) InsertAttestationDER(ctx context.Context, der []byte, proverkey []byte, verifierkey []byte) error {
// 	todo integrate prover and verifier keys
// 	par, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
// 		DER: der,
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	return e.InsertAttestation(ctx, par.Attestation)
// }

//External function: insert a DOT learned out of band
func (e *Engine) InsertAttestation(ctx context.Context, att *iapi.Attestation) error {
	//this must go into pending even if decryptable
	//to avoid racing with the labelled->active stuff
	return e.insertPendingAttestationSync(att, true)
}

//External function: get dots granted from an entity on a namespace.
//global grants will also be returned. The returned channel must be consumed
//completely, or the context must be cancelled
func (e *Engine) LookupAttestationsFrom(ctx context.Context, entityHash iapi.HashSchemeInstance, filter *iapi.LookupFromFilter) (chan *LookupResult, chan error) {
	subctx, cancel := context.WithCancel(context.WithValue(ctx, consts.PerspectiveKey, e.perspective))
	rv := make(chan *LookupResult, 10)
	rve := make(chan error, 1)
	go func() error {
		defer cancel()
		fin := func(e error) error {
			if e == nil {
				close(rv)
				close(rve)
				return e
			}
			rve <- e
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
			case rv <- &LookupResult{
				Attestation: res.Attestation,
				Validity:    validity,
			}:
			case <-subctx.Done():
				return fin(subctx.Err())
			}
		}
		return fin(nil)
	}()
	return rv, rve
}

func (e *Engine) LookupAttestationsTo(ctx context.Context, entityHash iapi.HashSchemeInstance, filter *iapi.LookupFromFilter) (chan *LookupResult, chan error) {
	//The external context does not have our perspective, but we want it so the caller
	//can cancel
	subctx, cancel := context.WithCancel(context.WithValue(ctx, consts.PerspectiveKey, e.perspective))
	rv := make(chan *LookupResult, 10)
	rve := make(chan error, 1)
	go func() error {
		defer cancel()
		fin := func(e error) error {
			if e == nil {
				close(rv)
				close(rve)
				return e
			}
			rve <- e
			//close(rv)
			//close(rve)
			return e
		}
		for res := range e.ws.GetActiveAttestationsToP(subctx, entityHash, filter) {
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
			case rv <- &LookupResult{
				Attestation: res.Attestation,
				Validity:    validity,
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
	StorageStatus       map[string]iapi.StorageDriverStatus
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
	stat, err := e.st.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &SyncStatus{
		WaitSyncEmpty:       sq,
		StorageStatus:       stat,
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

func (e *Engine) ResyncEntireGraph(ctx context.Context) error {
	ctx = context.WithValue(ctx, consts.PerspectiveKey, e.perspective)
	return e.updateAllInterestingEntities(ctx)
}

//
// //We should have a function that allows applications to tap into perspective changes
// //for the purposes of alerts and so on (also avoiding polling)
// func (e *Engine) SubscribePerspectiveChanges(ctx context.Context, someAdditionStuff string) {
// 	panic("ni")
// }
//
// //For things like brokers, they will want to subscribe to changes on dots and
// //entities used in active subscriptions, rather than polling
// func (e *Engine) SubscribeRevocations(ctx context.Context, interesting [][]byte) {
// 	panic("ni")
// }

//This should try find and decrypt a dot given the hash and aesk. No information from our
//perspective (active entity) is used
func (e *Engine) LookupAttestationNoPerspective(ctx context.Context, hash iapi.HashSchemeInstance, verifierKey []byte, location iapi.LocationSchemeInstance) (*iapi.Attestation, *Validity, error) {
	//First get the DOT from cache. This will come back decrypted if we know about it:
	att, err := e.ws.GetAttestationP(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	var der []byte
	if att == nil {
		//We need to try retrieve it from storage
		att, err = e.st.GetAttestation(ctx, location, hash)
		if err != nil {
			return nil, nil, err
		}
		if att == nil {
			return nil, nil, nil
		}
		der, err = att.DER()
		if err != nil {
			return nil, nil, err
		}
	} else {
		//We have the attestation but we need to "unparse it"
		der, err = att.DER()
		if err != nil {
			panic(err)
		}

	}

	//Don't give it our engine, so it can't use our perspective
	dctx := NewEngineDecryptionContext(nil)
	dctx.SetVerifierKey(verifierKey)
	par, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
		DER:               der,
		DecryptionContext: dctx,
	})
	if err != nil {
		return nil, nil, err
	}
	if par.IsMalformed {
		return nil, &Validity{
			Malformed: true,
		}, nil
	}

	//Ok now check the attestation
	validity, err := e.CheckAttestation(ctx, par.Attestation)
	return par.Attestation, validity, err
}

func (e *Engine) LookupAttestationInPerspective(ctx context.Context, hash iapi.HashSchemeInstance, location iapi.LocationSchemeInstance) (*iapi.Attestation, *Validity, error) {
	subctx := context.WithValue(ctx, consts.PerspectiveKey, e.perspective)
	att, err := e.ws.GetAttestationP(subctx, hash)
	if err != nil {
		return nil, nil, err
	}
	if att != nil {
		val, err := e.CheckAttestation(subctx, att)
		return att, val, err
	}

	//We need to fetch it from storage
	//We need to try retrieve it from storage
	att, err = iapi.SI().GetAttestation(subctx, location, hash)
	if err != nil {
		return nil, nil, err
	}
	if att == nil {
		return nil, nil, nil
	}

	//Don't give it our engine, so it can't use our perspective
	dctx := NewEngineDecryptionContext(e)
	par, err := iapi.ParseAttestation(subctx, &iapi.PParseAttestation{
		Attestation:       att,
		DecryptionContext: dctx,
	})
	if err != nil {
		return nil, nil, err
	}
	if par.IsMalformed {
		return nil, &Validity{
			Malformed: true,
		}, nil
	}

	//Ok now check the attestation
	validity, err := e.CheckAttestation(subctx, par.Attestation)
	return par.Attestation, validity, err
}

//Unlike checkDot, this should not touch the DB, it is a read-only operation
func (e *Engine) CheckAttestation(ctx context.Context, d *iapi.Attestation) (*Validity, error) {
	subjecth, subjloc := d.Subject()
	subject, err := e.getEntityFromHashLoc(ctx, subjecth, subjloc)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return &Validity{
			DstInvalid: true,
			Message:    "Subject entity unknown",
		}, nil
	}
	dstvalid, err := e.CheckEntity(ctx, subject)
	if err != nil {
		return nil, err
	}
	if !dstvalid.Valid {
		return &Validity{
			DstInvalid: true,
			Message:    fmt.Sprintf("Subject invalid: %s", dstvalid.Message),
		}, nil
	}

	if d.DecryptedBody == nil {
		return &Validity{
			NotDecrypted: true,
			Message:      "Attestation encrypted",
		}, nil
	}

	attesterh, attesterloc, err := d.Attester()
	if err != nil {
		return nil, err
	}
	attester, err := e.getEntityFromHashLoc(ctx, attesterh, attesterloc)
	if err != nil {
		return nil, err
	}
	if attester == nil {
		return &Validity{
			SrcInvalid: true,
			Message:    "Attester entity unknown",
		}, nil
	}
	srcvalid, err := e.CheckEntity(ctx, attester)
	if err != nil {
		return nil, err
	}
	if !srcvalid.Valid {
		return &Validity{
			SrcInvalid: true,
			Message:    fmt.Sprintf("Attester invalid: %s", srcvalid.Message),
		}, nil
	}
	exp, err := d.Expired()
	if err != nil {
		return &Validity{
			Expired: true,
			Message: fmt.Sprintf("Could not check expiry: %v", err.Error()),
		}, nil
	}
	if exp {
		return &Validity{
			Expired: true,
			Message: fmt.Sprintf("Attestation expired"),
		}, nil
	}
	return &Validity{
		Valid: true,
	}, nil
}
func (e *Engine) CheckEntity(ctx context.Context, ent *iapi.Entity) (*Validity, error) {
	if ent.Expired() {
		return &Validity{Valid: false, Expired: true, Message: "Entity expired"}, nil
	}
	// revoked, err := e.IsRevoked(e.ctx, ent.RevocationHash)
	// if err != nil {
	// 	return nil, err
	// }
	// if revoked {
	// 	return &Validity{Valid: false, Revoked: true}, nil
	// }
	return &Validity{Valid: true}, nil
}

func (e *Engine) LookupEntity(ctx context.Context, hash iapi.HashSchemeInstance, loc iapi.LocationSchemeInstance) (*iapi.Entity, *Validity, error) {
	ctx = context.WithValue(ctx, consts.PerspectiveKey, e.perspective)
	ent, err := e.ws.GetEntityByHashSchemeInstanceG(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	if ent != nil {
		val, err := e.CheckEntity(ctx, ent)
		return ent, val, err
	}

	//Get it from storage
	ent, err = e.st.GetEntity(ctx, loc, hash)
	if err != nil || ent == nil {
		return nil, nil, err
	}

	val, err := e.CheckEntity(ctx, ent)
	return ent, val, err
}

// //TODO this function should do some caching
// func (e *Engine) IsRevoked(ctx context.Context, hash []byte) (bool, error) {
// 	pani
// 	rvk, _, err := e.st.RetrieveRevocation(ctx, hash)
// 	if err != nil {
// 		return false, err
// 	}
// 	if rvk != nil {
// 		return true, nil
// 	}
// 	return false, nil
// }
