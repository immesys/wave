package engine

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	"github.com/stretchr/testify/require"
)

var ws iapi.WaveState
var inmem iapi.LocationSchemeInstance

func init() {
	//Do the storage
	go memoryserver.Main()
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	inmem = iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	si, err := overlay.NewOverlay(cfg)
	if err != nil {
		panic(err)
	}
	iapi.InjectStorageInterface(si)
	//Do the wave state
	tdir, _ := ioutil.TempDir("", "lls")
	llsdb, err := lls.NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
	ws = poc.NewPOC(llsdb)
}
func TestAttestationOneHop(t *testing.T) {
	ctx := context.Background()
	src, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	dst, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	//Create the attestation
	pol, err := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, err := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          src.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           dst.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)

	readback, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	require.NoError(t, err)
	atthash, err := iapi.SI().PutAttestation(context.Background(), inmem, readback.Attestation)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, src.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, dst.EntitySecrets.Entity)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, dst.EntitySecrets.Entity.Keccak256HI(), atthash)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), dst.EntitySecrets)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	clr, cerr := eng.LookupAttestationsFrom(ctx, src.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				return
			}
			fmt.Printf("got c:\n")
			spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			return
		}
	}
}
