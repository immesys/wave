package dot

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/wave/dot/objs"
	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/params"
)

type stub struct {
	source *entity.Entity
	dst    *entity.Entity
}

func (s *stub) DestEntity() *entity.Entity {
	return s.dst
}
func (s *stub) SourceEntity() *entity.Entity {
	return s.source
}
func (s *stub) EntityFromHash(ctx context.Context, h []byte) (*entity.Entity, error) {
	if bytes.Equal(s.source.Hash, h) {
		return s.source, nil
	}
	if bytes.Equal(s.dst.Hash, h) {
		return s.dst, nil
	}
	panic("huh")
}
func (s *stub) Auditors() [][]byte {
	return [][]byte{}
}

func (s *stub) OAQUEKeysForPartitionLabel(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return s.OAQUEKeysFor(ctx, vk, slots, onResult)
}
func (s *stub) OAQUEKeysForContent(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	return s.OAQUEKeysFor(ctx, vk, slots, onResult)
}
func (s *stub) OAQUEKeysFor(ctx context.Context, vk []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error {
	var params *oaque.Params
	var mk *oaque.MasterKey
	if bytes.Equal(s.dst.VK, vk) {
		params = s.dst.Params
		mk = s.dst.MasterKey
	} else {
		panic("unknown vk")
	}
	pk, e := oaque.KeyGen(nil, params, mk, slotsToAttrMap(slots))
	if e != nil {
		panic(e)
	}
	onResult(pk)
	return nil
}
func (s *stub) OAQUEPartitionKeysFor(ctx context.Context, vk []byte) ([]*oaque.PrivateKey, error) {
	gk := globalpartitionkey()
	//fmt.Printf("dp is %v\n, dstm")
	gpk, e := oaque.KeyGen(nil, s.dst.Params, s.dst.MasterKey, slotsToAttrMap(gk))
	if e != nil {
		panic(e)
	}
	nsk := partitionkey([]byte("namespace"))
	npk, e := oaque.KeyGen(nil, s.dst.Params, s.dst.MasterKey, slotsToAttrMap(nsk))
	if e != nil {
		panic(e)
	}
	return []*oaque.PrivateKey{gpk, npk}, nil
}
func (s *stub) OAQUEDelegationKeyFor(ctx context.Context, vk []byte, partition [][]byte) (*oaque.PrivateKey, error) {
	pk, e := oaque.KeyGen(nil, s.dst.Params, s.dst.MasterKey, slotsToAttrMap(partition))
	if e != nil {
		panic(e)
	}
	return pk, nil
}

func TestSerdes(t *testing.T) {
	st := stub{}
	st.source = entity.NewEntity(params.LocationUC)
	st.dst = entity.NewEntity(params.LocationUC)

	dot := objs.DOT{}
	dot.Content = &objs.DOTContent{
		SRC:         st.source.Hash,
		DST:         st.dst.Hash,
		URI:         "CSnDzka2Nuu5e0UmOR6FH9YEYwIdEx5GwaD_ms9rDV0=/foo/bard",
		Permissions: []string{"wave:publish"},
	}
	dot.PlaintextHeader = &objs.PlaintextHeader{
		DST: st.dst.Hash,
	}
	dot.PartitionLabel = make([][]byte, params.OAQUESlots)
	dot.PartitionLabel[0] = []byte(OAQUEMetaSlotPartition)
	dot.PartitionLabel[1] = []byte("hello")
	dot.Inheritance = &objs.InheritanceMap{}
	representation, err := EncryptDOT(dot, &st)
	if err != nil {
		panic(err)
	}
	_ = representation
	ddot, err := DecryptFullDOT(context.Background(), representation, &st)
	_ = ddot
	fmt.Printf("decode error was: %v\n", err)
	spew.Dump(ddot)
	//Test deserialization
}
