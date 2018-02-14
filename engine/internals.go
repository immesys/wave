package engine

import (
	"context"
	"sync"

	"github.com/immesys/wave/iapi"
	localdb "github.com/immesys/wave/localdb/types"
	"github.com/immesys/wave/storage"
)

//how to develop this?
// guiding principles: we don't take an action based on a new BC event
// but rather based on a task
// BUT we may also trigger some tasks based on observed logs blooms
// in the block headers
// actions:
//  A) update an entity (fields, attestations)
//  B) update dot index (dstvk, index)
//  C) add out-of-band DOT
// b+c will trigger further actions that must get added to the work queue

// When agent first starts, all interesting entities will be updated.
// after that, updates are triggered by header block blooms
// There is one engine per perspective (a perspective is a controlling entity)
type Engine struct {
	ctx       context.Context
	ctxcancel context.CancelFunc

	ws          localdb.WaveState
	st          storage.Storage
	perspective *iapi.Entity

	//If a dot enters labelled, it must be tested against all keys
	//to ensure none of them match before entering labelled.
	//Similarly, if a new content key is added, it must be tested
	//against all labelled dots before being added.
	//we don't resync, so these operations must NOT happen concurrently
	//or be forgotten about.
	//map of string entity hash to mutex
	//I would have wanted to partition this by hash or something
	//so there are multiple locks, but we don't know the hash of the
	//source until we decrypt it so we can't lock on it :p
	partitionMutex sync.Mutex

	//The queue of entities that need to be synced
	resyncQueue chan [32]byte

	//For sync status
	totalMutex sync.Mutex

	//This channel is closed whenever the two totals are equal
	//and replaced whenever they become nonequal again
	//only read it while golting totalMutex
	totalEqual          chan struct{}
	totalSyncRequests   int64
	totalCompletedSyncs int64
}

func NewEngine(ctx context.Context, state localdb.WaveState, bchain storage.Storage, perspective *iapi.Entity) (*Engine, error) {
	subctx, cancel := context.WithCancel(ctx)
	var err error
	rv := Engine{
		ctx:         subctx,
		ctxcancel:   cancel,
		ws:          state,
		st:          bchain,
		perspective: perspective,
		totalEqual:  make(chan struct{}),
		//TODO make buffered. Unbuffered for now to find deadlocks
		resyncQueue: make(chan [32]byte),
	}

	//This function must only return once it knows that it has started watching
	//we don't want a race/gap between processing new and processing old
	err = rv.watchHeaders()
	if err != nil {
		rv.ctxcancel()
		return nil, err
	}
	//This will process all the old interesting entities
	err = rv.updateAllInterestingEntities(subctx)
	if err != nil {
		rv.ctxcancel()
		return nil, err
	}
	//The engine is now running and ready for use
	return &rv, nil
}

// For as long as the engine's context is active, watch and process new
// events on the chain
func (e *Engine) watchHeaders() error {
	//This channel should be sized to buffer the number of logs that can reasonably
	//appear in a single block, but nothing bad happens if wrong
	rch := make(chan *storage.ChangeEvent, 1000)
	//If the engine context is cancelled, we want to cancel our subscription too
	err := e.st.SubscribeStorageChange(e.ctx, rch)
	if err != nil {
		return err
	}
	go func() {
		for change := range rch {
			e.handleStorageEvent(change)
		}
	}()
	return nil
}
