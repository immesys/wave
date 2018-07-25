package eapi

import (
	"bytes"
	"context"
	"sort"

	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/immesys/wave/eapi/pb"
	"github.com/stretchr/testify/require"
)

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

type bcel struct {
	DER  []byte
	Body *pb.AttestationBody
}
type lbcel []*bcel

// Len is the number of elements in the collection.
func (b lbcel) Len() int {
	return len(b)
}

// Less reports whether the element with
// index i should sort before the element with index j.
func (b lbcel) Less(i, j int) bool {
	return bytes.Compare(b[i].DER, b[j].DER) < 0
}

// Swap swaps the elements with indexes i and j.
func (b lbcel) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
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

	resp, err := eapi.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER: rv.ProofDER,
	})
	require.NoError(tst, err)
	require.Nil(tst, resp.Error)
	//We want to be sure the same attestations are included in both, but for
	//multipath proofs, the order of the actual elements can differ
	//so make two lists and sort them

	buildList := []*bcel{}
	proofList := []*bcel{}
	for _, el := range rv.Result.Elements {
		el.Body.DecodedBodyDER = nil
		buildList = append(buildList, &bcel{
			DER:  el.DER,
			Body: el.Body,
		})
	}
	for _, el := range resp.Result.Elements {
		el.Body.DecodedBodyDER = nil
		proofList = append(proofList, &bcel{
			DER:  el.DER,
			Body: el.Body,
		})
	}
	sort.Sort(lbcel(buildList))
	sort.Sort(lbcel(proofList))
	require.EqualValues(tst, buildList, proofList)
	//
	// for idx, _ := range resp.Result.Elements {
	// 	resp.Result.Elements[idx].Body.DecodedBodyDER = nil
	// 	rv.Result.Elements[idx].Body.DecodedBodyDER = nil
	// 	require.EqualValues(tst, resp.Result.Elements[idx].DER, rv.Result.Elements[idx].DER)
	// 	require.EqualValues(tst, resp.Result.Elements[idx].Body, rv.Result.Elements[idx].Body)
	// 	//fmt.Printf("expiry RESP %3d %d\n", idx, resp.Result.Elements[idx].Body.ValidUntil)
	// 	//fmt.Printf("expiry   RV %3d %d\n", idx, rv.Result.Elements[idx].Body.ValidUntil)
	// }
	//require.EqualValues(tst, resp.Result.Policy, rv.Result.Policy)
	require.EqualValues(tst, resp.Result.Expiry, rv.Result.Expiry)
	if diff := deep.Equal(resp.Result.Policy, rv.Result.Policy); diff != nil {
		tst.Error(diff)
	}
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
			//Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: perspective,
	})
	require.NoError(tst, err)
	require.Nil(tst, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: perspective,
		})
		require.NoError(tst, err)
		require.Nil(tst, ss.Error)
		fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("==================== STARTING BUILD IN DESTINATION GRAPH ========================\n")
	permarr := []string{}
	pbits, err := strconv.ParseInt(perms, 2, 64)
	require.NoError(tst, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
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
				//	Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     t.pubs[dst].Hash,
		SubjectLocation: &inmem,
		Policy:          pbpolicy,
	})
	require.NoError(tst, err)
	require.Nil(tst, att.Error)
	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(tst, err)
	require.Nil(tst, pubresp.Error)
}

func TestRTreeSimpleExisting(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "1", 1)
	tg.BuildCompare(t, "a", "1", 1, 1)
}
func TestRTreeSimpleNonExisting(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "1", 1)
	tg.Edge(t, "b", "c", "1", 1)
	tg.BuildCompare(t, "c", "1", -1, -1)

}
func TestRTreeSimpleNonExistingTTL(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "1", 0)
	tg.Edge(t, "a", "b", "1", 1)
	tg.BuildCompare(t, "b", "1", -1, -1)
}
func TestRTreeSimpleNonExistingPerms(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "111", 5)
	tg.Edge(t, "a", "b", "101", 5)
	tg.BuildCompare(t, "b", "111", -1, -1)
}
func TestRTreeSimpleDual(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "10", 5)
	tg.Edge(t, "ns", "b", "01", 5)
	tg.Edge(t, "b", "c", "11", 5)
	tg.Edge(t, "a", "c", "11", 5)
	tg.BuildCompare(t, "c", "11", 4, 4)
}
func TestRTreeSubPerm(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "11", 0)
	tg.BuildCompare(t, "a", "01", 1, 0)
}
