package engine

import (
	"context"

	"github.com/immesys/wave/dot"
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
func (e *Engine) LookupDOTSFrom(ctx context.Context, entityHash []byte) (chan *dot.DOT, chan error) {
	panic("ni")
}

//This should try find and decrypt a dot given the hash and aesk. No information from our
//perspective (active entity) is used
func (e *Engine) LookupDotNoPerspective(ctx context.Context, hash []byte, aesk []byte, location int64) (*dot.DOT, error) {
	panic("ni")
}

func (e *Engine) LookupDotInPerspective(ctx context.Context, hash []byte) (*dot.DOT, error) {
	panic("ni")
}
