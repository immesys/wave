package dot

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot/objs"
)

type stub struct {
	sk []byte
	vk []byte

	dstsk      []byte
	dstvk      []byte
	dp         *oaque.Params
	srcp       *oaque.Params
	srcmk      oaque.MasterKey
	dstmk      oaque.MasterKey
	namespaces []string
}

func (s *stub) SourceKeys() (sk []byte, vk []byte) {
	return s.sk, s.vk
}
func (s *stub) DstOAQUEParams() *oaque.Params {
	return s.dp
}
func (s *stub) SrcOAQUEParams() (*oaque.Params, oaque.MasterKey) {
	return s.srcp, s.srcmk
}
func (s *stub) Auditors() [][]byte {
	return [][]byte{}
}

func (s *stub) NamespaceHints() []string {
	return s.namespaces
}
func (s *stub) OurOAQUEKey(vk []byte) oaque.MasterKey {
	return s.dstmk
}
func (s *stub) OAQUEParamsForVK(ctx context.Context, vk []byte) (*oaque.Params, error) {
	return s.dp, nil
}
func (s *stub) OurSK(vk []byte) []byte {
	return s.dstsk
}
func (s *stub) OAQUEPartitionKeysFor(ctx context.Context, vk []byte) ([]*oaque.PrivateKey, error) {
	gk := globalpartitionkey()
	//fmt.Printf("dp is %v\n, dstm")
	gpk, e := oaque.KeyGen(nil, s.dp, s.dstmk, idToAttrMap(gk))
	if e != nil {
		panic(e)
	}
	nsk := partitionkey("namespace")
	npk, e := oaque.KeyGen(nil, s.dp, s.dstmk, idToAttrMap(nsk))
	if e != nil {
		panic(e)
	}
	return []*oaque.PrivateKey{gpk, npk}, nil
}
func (s *stub) OAQUEDelegationKeyFor(ctx context.Context, vk []byte, partition string) (*oaque.PrivateKey, error) {
	pk, e := oaque.KeyGen(nil, s.dp, s.dstmk, idToAttrMap(partition))
	if e != nil {
		panic(e)
	}
	return pk, nil
}

func TestSerdes(t *testing.T) {
	st := stub{}
	st.sk, st.vk = crypto.GenerateKeypair()
	st.dstsk, st.dstvk = crypto.GenerateKeypair()
	aP, aMK, err := oaque.Setup(rand.Reader, 4)
	if err != nil {
		panic(err)
	}
	bP, bMK, err := oaque.Setup(rand.Reader, 4)
	if err != nil {
		panic(err)
	}
	st.dp = bP
	_ = bMK
	st.srcp = aP
	st.srcmk = aMK
	st.dstmk = bMK
	//st.namespaces = []string{"namespace"}
	dot := objs.DOT{}
	dot.Content = &objs.DOTContent{
		SRCVK:       st.vk,
		DSTVK:       st.dstvk,
		URI:         "namespace/foo/bard",
		Permissions: []string{"wave:publish"},
	}
	dot.PlaintextHeader = &objs.PlaintextHeader{
		DSTVK: st.dstvk,
	}
	dot.PartitionLabel = "foo/bar"
	dot.Inheritance = &objs.InheritanceMap{}
	representation, err := EncryptDOT(dot, &st)
	if err != nil {
		panic(err)
	}
	_ = representation
	ddot, err := DecryptDOT(context.Background(), representation, &st)
	_ = ddot
	fmt.Printf("decode error was: %v\n", err)
	spew.Dump(ddot)
	//Test deserialization
}
