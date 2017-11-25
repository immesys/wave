package engine

import (
	"context"

	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
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
}

type Filter struct {
	//Like namespace and permissions and stuff
	//backend might be able to index some of it
	//also validity
}

type LookupResult struct {
	//The dot but also its validity
}

// received proof:

// TODO formulate dots decoded with AESK
// TODO how to decrypt a dot that you granted yourself?

//External function: insert a DOT learned out of band
func (e *Engine) InsertDOT(ctx context.Context, encodedDOT []byte) error {
	panic("ni")
}

//External function: get dots granted from an entity on a namespace.
//global grants will also be returned. The returned channel must be consumed
//completely, or the context must be cancelled
func (e *Engine) LookupDOTSFrom(ctx context.Context, entityHash []byte, filter *Filter) (chan *LookupResult, chan error) {
	panic("ni")
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
func (e *Engine) LookupDotNoPerspective(ctx context.Context, hash []byte, aesk []byte, location int64) (*dot.DOT, *Validity, error) {
	panic("ni")
}

func (e *Engine) LookupDotInPerspective(ctx context.Context, hash []byte) (*dot.DOT, *Validity, error) {
	panic("ni")
}

func (e *Engine) LookupEntity(ctx context.Context, hash []byte) (*entity.Entity, *Validity, error) {
	panic("ni")
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
