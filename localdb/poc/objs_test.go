package poc

import (
	"testing"

	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/params"
)

func TestEntityState(t *testing.T) {
	es := &EntityState{
		Entity:           entity.NewEntity(params.LocationUC),
		State:            5,
		DotIndex:         7,
		MaxLabelKeyIndex: 10,
	}
	blob, err := es.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	res := &EntityState{}
	_, err = res.UnmarshalMsg(blob)
	if err != nil {
		t.Fatal(err)
	}
}
