package engine

import (
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
)

//Check for revocations
//If decoded, check for expiry and entRevoked
//This must be fairly fast as it gets called frequently on the same stuff
func (e *Engine) checkDot(d *dot.DOT) (okay bool, err error) {
	panic("ni")
	//this should call checkEntity on both
}

//Like checkDot but don;t update db
func (e *Engine) checkDotNoHandle(d *dot.DOT) (okay bool, err error) {
	panic("ni")
	//this should call checkEntity on both
}

func (e *Engine) checkEntity(ent *entity.Entity) (bool, error) {
	panic("ni")
}

//Like check entity but don't update the DB
func (e *Engine) checkEntityNoHandle(ent *entity.Entity) (bool, error) {
	panic("ni")
}
