package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	"google.golang.org/grpc"
)

const logServer = "localhost:8092"
const mapServer = "localhost:8090"

var PublicKey string
var PrivateKey string

func mustMarshalAny(pb proto.Message) *any.Any {
	value, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err)
	}
	return value
}

func initlog(displayname string) {
	pubk, _ := pem.Decode([]byte(PublicKey))
	privk, _ := pem.Decode([]byte(PrivateKey))
	LogTree := &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        displayname,
		Description:        "for WAVE",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: privk.Bytes,
		}),
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	var err error
	ctx := context.Background()
	logconn, err := grpc.Dial(logServer, grpc.WithInsecure())
	if err != nil {
		glog.Fatal(err)
	}
	adm := trillian.NewTrillianAdminClient(logconn)
	respct, err := adm.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: LogTree,
	})
	if err != nil {
		panic(err)
	}
	treeId := respct.TreeId
	LogTree.TreeId = treeId
	fmt.Printf("export VLDM_TREE_%s=%d\n", displayname, treeId)
	vlog := trillian.NewTrillianLogClient(logconn)
	_, err = vlog.InitLog(ctx, &trillian.InitLogRequest{
		LogId: treeId,
	})
	if err != nil {
		panic(err)
	}
}

func initmap(displayname string) {
	pubk, _ := pem.Decode([]byte(PublicKey))
	privk, _ := pem.Decode([]byte(PrivateKey))
	var err error
	MapTree := &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        displayname,
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
	mapconn, err := grpc.Dial(mapServer, grpc.WithInsecure())
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
	mapId := respct.TreeId
	MapTree.TreeId = mapId
	fmt.Printf("export VLDM_TREE_%s=%d\n", displayname, mapId)
	vmap := trillian.NewTrillianMapClient(mapconn)
	_, err = vmap.InitMap(ctx, &trillian.InitMapRequest{
		MapId: mapId,
	})
	if err != nil {
		panic(err)
	}
}

func main() {
	pub, err := ioutil.ReadFile("vldm_public.pem")
	if err != nil {
		fmt.Printf("could not read public key: %v\n", err)
		os.Exit(1)
	}
	priv, err := ioutil.ReadFile("vldm_private.pem")
	if err != nil {
		fmt.Printf("could not read private key: %v\n", err)
		os.Exit(1)
	}
	PublicKey = string(pub)
	PrivateKey = string(priv)
	initlog("OPERATIONS")
	initlog("MAPROOTS")
	initmap("MAP")
}
