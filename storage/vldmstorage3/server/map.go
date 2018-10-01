package main

import (
	"encoding/pem"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	"google.golang.org/grpc"
)

var MapTree *trillian.Tree
var mapconn *grpc.ClientConn
var vmap trillian.TrillianMapClient

func initmap() {
	pubk, _ := pem.Decode([]byte(PublicKey))
	privk, _ := pem.Decode([]byte(PrivateKey))
	var err error
	MapTree = &trillian.Tree{
		TreeId:             TreeID_Map,
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "MAP",
		Description:        "Storage of attestations and entities for WAVE",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: privk.Bytes,
		}),
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}

	mapconn, err = grpc.Dial(mapServer, grpc.WithInsecure())
	if err != nil {
		glog.Fatal(err)
	}
	vmap = trillian.NewTrillianMapClient(mapconn)
	API.mapId = TreeID_Map
}

// func addToMap(key []byte, val []byte) (*trillian.SignedMapRoot, *trillian.MapLeafInclusion) {
// 	ctx := context.Background()
// 	idx := make([]byte, 32)
// 	rand.Read(idx)
// 	lvs := []*trillian.MapLeaf{
// 		&trillian.MapLeaf{
// 			Index:     key,
// 			LeafValue: val,
// 		},
// 	}
// 	resp, err := vmap.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
// 		MapId:  mapId,
// 		Leaves: lvs,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	_ = resp
// 	resp2, err := vmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
// 		MapId: mapId,
// 		Index: [][]byte{key},
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	MapVerifier, err := client.NewMapVerifierFromTree(MapTree)
// 	if err != nil {
// 		panic(err)
// 	}
// 	err = MapVerifier.VerifyMapLeafInclusion(resp2.MapRoot, resp2.MapLeafInclusion[0])
// 	if err != nil {
// 		panic(err)
// 	}
// 	return resp2.MapRoot, resp2.MapLeafInclusion[0]
// 	//
// 	// mv, err := client.NewMapVerifierFromTree(MapTree)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// err = mv.VerifyMapLeafInclusion(resp2.MapRoot, resp2.MapLeafInclusion[0])
// 	// if err != nil {
// 	// 	panic(err)
// 	// } else {
// 	// 	fmt.Printf("verified inclusion ok\n")
// 	// }
// }
