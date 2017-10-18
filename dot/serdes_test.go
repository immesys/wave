package dot

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/hibe"
	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot/objs"
)

type stub struct {
	sk []byte
	vk []byte

	dstsk      []byte
	dstvk      []byte
	dp         *hibe.Params
	srcp       *hibe.Params
	srcmk      hibe.MasterKey
	dstmk      hibe.MasterKey
	namespaces []string
}

func (s *stub) SourceKeys() (sk []byte, vk []byte) {
	return s.sk, s.vk
}
func (s *stub) DstHIBEParams() *hibe.Params {
	return s.dp
}
func (s *stub) SrcHIBEParams() (*hibe.Params, hibe.MasterKey) {
	return s.srcp, s.srcmk
}
func (s *stub) Auditors() [][]byte {
	return [][]byte{}
}

func (s *stub) NamespaceHints() []string {
	return s.namespaces
}
func (s *stub) OurHIBEKey(vk []byte) hibe.MasterKey {
	return s.dstmk
}
func (s *stub) HIBEParamsForVK(vk []byte) *hibe.Params {
	return s.dp
}
func (s *stub) OurSK(vk []byte) []byte {
	return s.dstsk
}
func (s *stub) HIBEPartitionKeysFor(vk []byte) []*hibe.PrivateKey {
	gk := globalpartitionkey()
	//fmt.Printf("dp is %v\n, dstm")
	gpk, e := hibe.KeyGenFromMaster(rand.Reader, s.dp, s.dstmk, idToInts(gk))
	if e != nil {
		panic(e)
	}
	nsk := partitionkey("namespace")
	npk, e := hibe.KeyGenFromMaster(rand.Reader, s.dp, s.dstmk, idToInts(nsk))
	if e != nil {
		panic(e)
	}
	return []*hibe.PrivateKey{gpk, npk}
}
func (s *stub) HIBEDelegationKeyFor(vk []byte, partition string) *hibe.PrivateKey {
	pk, e := hibe.KeyGenFromMaster(rand.Reader, s.dp, s.dstmk, idToInts(partition))
	if e != nil {
		panic(e)
	}
	return pk
}

func TestSerdes(t *testing.T) {
	st := stub{}
	st.sk, st.vk = crypto.GenerateKeypair()
	st.dstsk, st.dstvk = crypto.GenerateKeypair()
	aP, aMK, err := hibe.Setup(rand.Reader, 4)
	if err != nil {
		panic(err)
	}
	bP, bMK, err := hibe.Setup(rand.Reader, 4)
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
	ddot, err := DecryptDOT(representation, &st)
	_ = ddot
	fmt.Printf("decode error was: %v\n", err)
	spew.Dump(ddot)
	//Test deserialization
}
