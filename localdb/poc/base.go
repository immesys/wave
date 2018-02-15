package poc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"strings"

	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/iapi"
)

type poc struct {
	u iapi.LowLevelStorage
}

func NewPOC(lls iapi.LowLevelStorage) iapi.WaveState {
	return &poc{u: lls}
}

//Ensure we match the interface
var _ iapi.WaveState = &poc{}

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
	perspective := ctx.Value(consts.PerspectiveKey)
	//Do it as hex to ensure we can use "/" as a separator
	//for the sake of a perspective key it is ok to have only one type of hash
	hshi, err := perspective.(*iapi.EntitySecrets).Entity.Hash(ctx, iapi.KECCAK256)
	if err != nil {
		panic(err)
	}
	hsh := hshi.Value()

	ph := ToB64(hsh)
	parts := []string{ph}
	parts = append(parts, stuff...)
	return strings.Join(parts, "/")
}

func unmarshalGob(ba []byte, into interface{}) error {
	buf := bytes.NewBuffer(ba)
	dec := gob.NewDecoder(buf) // Will read from network.
	return dec.Decode(into)
}
func marshalGob(from interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(from)
	return buf.Bytes(), err
}
