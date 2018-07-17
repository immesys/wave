package main

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	"google.golang.org/grpc"
)

const mapServer = "localhost:8090"

var MapTree *trillian.Tree
var mapconn *grpc.ClientConn
var vmap trillian.TrillianMapClient
var mapId int64

const PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmTz0jNtdPnob3U8uylM5PORUJPw2
9VEU8V68V8FtlxFxuuU6MFHzN5/3XnWCeJ0xJ1Uabk1r/eS0H7aWOksMNA==
-----END PUBLIC KEY-----`

const PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaK0u/I9YXTE7Yxb6
uGK3vX/KzWQVqCpqctv4hhAWEcuhRANCAASZPPSM210+ehvdTy7KUzk85FQk/Db1
URTxXrxXwW2XEXG65TowUfM3n/dedYJ4nTEnVRpuTWv95LQftpY6Sww0
-----END PRIVATE KEY-----`

func initmap() {
	pubk, _ := pem.Decode([]byte(PublicKey))
	privk, _ := pem.Decode([]byte(PrivateKey))
	var err error
	MapTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_CONIKS_SHA512_256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "WAVE Storage map",
		Description:        "Storage of attestations and entities for WAVE",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: privk.Bytes,
		}),
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}

	ctx := context.Background()
	mapconn, err = grpc.Dial(mapServer, grpc.WithInsecure())
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
	fmt.Printf("Map ID is %d\n", mapId)
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
	MapVerifier, err := client.NewMapVerifierFromTree(MapTree)
	if err != nil {
		panic(err)
	}
	err = MapVerifier.VerifyMapLeafInclusion(resp2.MapRoot, resp2.MapLeafInclusion[0])
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
