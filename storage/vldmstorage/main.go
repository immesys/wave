package main

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	ktestonly "github.com/google/trillian/crypto/keys/testonly"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/testonly"
	"google.golang.org/grpc"
)

const logServer = "localhost:8090"

var MapTree *trillian.Tree
var mapconn *grpc.ClientConn
var vmap trillian.TrillianMapClient
var mapId int64

func initmap() {
	MapTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_CONIKS_SHA512_256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "Llamas Map",
		Description:        "Key Transparency map for all your digital llama needs.",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: ktestonly.MustMarshalPrivatePEMToDER(testonly.DemoPrivateKey, testonly.DemoPrivateKeyPass),
		}),
		PublicKey: &keyspb.PublicKey{
			Der: ktestonly.MustMarshalPublicPEMToDER(testonly.DemoPublicKey),
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}

	ctx := context.Background()
	var err error
	mapconn, err = grpc.Dial(logServer, grpc.WithInsecure())
	if err != nil {
		glog.Fatal(err)
	}
	adm := trillian.NewTrillianAdminClient(mapconn)
	respct, err := adm.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: MapTree,
	})
	if err != nil {
		panic(err)
	}
	mapId = respct.TreeId
	MapTree.TreeId = mapId
	vmap = trillian.NewTrillianMapClient(mapconn)
	_, err = vmap.InitMap(ctx, &trillian.InitMapRequest{
		MapId: mapId,
	})
	if err != nil {
		panic(err)
	}
}
func addToMap(key []byte, val []byte) (*trillian.SignedMapRoot, *trillian.MapLeafInclusion) {
	ctx := context.Background()
	idx := make([]byte, 32)
	rand.Read(idx)
	lvs := []*trillian.MapLeaf{
		&trillian.MapLeaf{
			Index:     key,
			LeafValue: val,
		},
	}
	resp, err := vmap.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
		MapId:  mapId,
		Leaves: lvs,
	})
	if err != nil {
		panic(err)
	}
	_ = resp
	resp2, err := vmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId: mapId,
		Index: [][]byte{key},
	})
	if err != nil {
		panic(err)
	}
	return resp2.MapRoot, resp2.MapLeafInclusion[0]
	//
	// mv, err := client.NewMapVerifierFromTree(MapTree)
	// if err != nil {
	// 	panic(err)
	// }
	// err = mv.VerifyMapLeafInclusion(resp2.MapRoot, resp2.MapLeafInclusion[0])
	// if err != nil {
	// 	panic(err)
	// } else {
	// 	fmt.Printf("verified inclusion ok\n")
	// }
}
