package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"
	"time"

	exapi "github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	"github.com/stretchr/testify/require"
)

var eapi *exapi.EAPI
var inmem pb.Location

func createEntity(t *testing.T) (public []byte, secret []byte) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{})
	require.NoError(t, err)
	return rv.PublicDER, rv.SecretDER
}
func createAndPublishEntity(t *testing.T) (public []byte, secret []byte, hash []byte) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{})
	require.NoError(t, err)
	rvhash, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      rv.PublicDER,
		Location: &inmem,
	})
	return rv.PublicDER, rv.SecretDER, rvhash.Hash
}

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
	eapi = exapi.NewEAPI(ws)
}

type TestGraph struct {
	publics map[string][]byte
	secrets map[string][]byte
	pubs    map[string]*pb.PublishEntityResponse
}

func TG() *TestGraph {
	return &TestGraph{
		publics: make(map[string][]byte),
		secrets: make(map[string][]byte),
		pubs:    make(map[string]*pb.PublishEntityResponse),
	}
}
func (t *TestGraph) BuildCompare(tst *testing.T, dst string, perms string, edges int, ttl int) {
	rv := t.Build(tst, dst, perms)
	if edges == -1 {
		//No path is meant to exist
		require.NotNil(tst, rv.Error)
		require.EqualValues(tst, 911, rv.Error.Code)
		return
	}
	require.Nil(tst, rv.Error)
	require.EqualValues(tst, edges, len(rv.Result.Elements))
	require.EqualValues(tst, ttl, rv.Result.Policy.RTreePolicy.Indirections)
	then := time.Now()
	_, err := eapi.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER: rv.ProofDER,
	})
	fmt.Printf("TIMING proof verify took %s\n", time.Now().Sub(then))
	require.NoError(tst, err)
	// require.Nil(tst, resp.Error)
	// for idx, _ := range resp.Result.Elements {
	// 	resp.Result.Elements[idx].Body.DecodedBodyDER = nil
	// 	rv.Result.Elements[idx].Body.DecodedBodyDER = nil
	// 	require.EqualValues(tst, resp.Result.Elements[idx].DER, rv.Result.Elements[idx].DER)
	// 	require.EqualValues(tst, resp.Result.Elements[idx].Body, rv.Result.Elements[idx].Body)
	// }
	// require.EqualValues(tst, resp.Result.Policy, rv.Result.Policy)
	// require.EqualValues(tst, resp.Result.Expiry, rv.Result.Expiry)
	//require.EqualValues(tst, rv.Result, resp.Result)
	// if diff := deep.Equal(rv.Result, resp.Result); diff != nil {
	// 	tst.Error(diff)
	// }
}

func (t *TestGraph) Build(tst *testing.T, dst string, perms string) *pb.BuildRTreeResponse {
	ctx := context.Background()
	perspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: t.secrets[dst],
		},
		Location: &inmem,
	}
	then := time.Now()
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: perspective,
	})
	require.NoError(tst, err)
	require.Nil(tst, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	eapi.WaitForSyncCompleteHack(&pb.SyncParams{
		Perspective: perspective,
	})
	fmt.Printf("Sync complete: %s\n", time.Now().Sub(then))
	fmt.Printf("==================== STARTING BUILD IN DESTINATION GRAPH ========================\n")
	permarr := []string{}
	pbits, err := strconv.ParseInt(perms, 2, 64)
	require.NoError(tst, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	then = time.Now()
	resp, err := eapi.BuildRTreeProof(ctx, &pb.BuildRTreeParams{
		Perspective:    perspective,
		SubjectHash:    t.pubs[dst].Hash,
		RtreeNamespace: t.pubs["ns"].Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: t.pubs["ns"].Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	})
	fmt.Printf("TIMING Build complete: %s\n", time.Now().Sub(then))
	require.NoError(tst, err)
	return resp
}
func (t *TestGraph) Edge(tst *testing.T, src, dst string, perms string, ttl int) {
	ctx := context.Background()
	if t.pubs[src] == nil {
		t.publics[src], t.secrets[src] = createEntity(tst)
		var err error
		t.pubs[src], err = eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      t.publics[src],
			Location: &inmem,
		})
		require.NoError(tst, err)
	}
	if t.pubs[dst] == nil {
		t.publics[dst], t.secrets[dst] = createEntity(tst)
		var err error
		t.pubs[dst], err = eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      t.publics[dst],
			Location: &inmem,
		})
		require.NoError(tst, err)
	}
	permarr := []string{}
	pbits, err := strconv.ParseInt(perms, 2, 64)
	require.NoError(tst, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	policy := pb.RTreePolicy{
		Namespace:    t.pubs["ns"].Hash,
		Indirections: uint32(ttl),
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: t.pubs["ns"].Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	}
	pbpolicy := &pb.Policy{
		RTreePolicy: &policy,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: t.secrets[src],
			},
			Location: &inmem,
		},
		BodyScheme:      exapi.BodySchemeWaveRef1,
		SubjectHash:     t.pubs[dst].Hash,
		SubjectLocation: &inmem,
		Policy:          pbpolicy,
	})
	require.NoError(tst, err)
	require.Nil(tst, att.Error)
	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
	})
	require.NoError(tst, err)
	require.Nil(tst, pubresp.Error)
}
