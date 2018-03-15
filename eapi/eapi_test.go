package eapi

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	"github.com/stretchr/testify/require"
)

var eapi *eAPI
var inmem pb.Location

func init() {
	go memoryserver.Main()
	time.Sleep(100 * time.Millisecond)
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	//inmem := iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	inmem.LocationURI = &pb.LocationURI{
		URI:     "http://localhost:8080/v1",
		Version: 1,
	}
	si, err := overlay.NewOverlay(cfg)
	if err != nil {
		panic(err)
	}
	iapi.InjectStorageInterface(si)

	tdir, _ := ioutil.TempDir("", "lls")
	llsdb, err := lls.NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
	ws := poc.NewPOC(llsdb)
	eapi = NewEAPI(ws)
}

func TestCreateEntity(t *testing.T) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	require.NotNil(t, rv.PublicDER)
	require.NotNil(t, rv.SecretDER)
}

func TestCreateEntityNoPassphrase(t *testing.T) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{})
	require.NoError(t, err)
	require.NotNil(t, rv.PublicDER)
	require.NotNil(t, rv.SecretDER)
}

func createEntity(t *testing.T) (public []byte, secret []byte) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	return rv.PublicDER, rv.SecretDER
}

func TestCreateAttestation(t *testing.T) {
	ctx := context.Background()
	srcPublic, srcSecret := createEntity(t)
	dstPublic, dstSecret := createEntity(t)
	_ = dstSecret
	srcpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcPublic,
		Location: &inmem,
	})
	require.NoError(t, err)
	dstpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstPublic,
		Location: &inmem,
	})
	require.NoError(t, err)
	_ = dstpub
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     srcpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	_ = att
	require.NoError(t, err)
}
