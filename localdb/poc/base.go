package poc

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/localdb/types"
)

type poc struct {
	u types.LowLevelStorage
}

func NewPOC(lls types.LowLevelStorage) types.WaveState {
	return &poc{u: lls}
}

//Ensure we match the interface
var _ types.WaveState = &poc{}

func ToB64(arr []byte) string {
	return base64.URLEncoding.EncodeToString(arr)
}

func FromB64(s string) []byte {
	rv, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return rv
}

func split(s string) []string {
	return strings.SplitN(s, "/", -1)
}

func (p *poc) PKey(ctx context.Context, stuff ...string) string {
	perspective := ctx.Value(engine.PerspectiveKey)
	//Do it as hex to ensure we can use "/" as a separator
	ph := ToB64(perspective.(*entity.Entity).Hash)
	parts := []string{ph}
	parts = append(parts, stuff...)
	return strings.Join(parts, "/")
}
