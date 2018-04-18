package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	ktestonly "github.com/google/trillian/crypto/keys/testonly"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/testonly"
	"google.golang.org/grpc"
)

const mapServer = "localhost:8090"

func mustMarshalAny(pb proto.Message) *any.Any {
	value, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err)
	}
	return value
}

var logconn *grpc.ClientConn
var LogTree *trillian.Tree
var vlog trillian.TrillianLogClient
var logId int64

func initlog() {
	LogTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "Llamas Log",
		Description:        "Registry of publicly-owned llamas",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: ktestonly.MustMarshalPrivatePEMToDER(testonly.DemoPrivateKey, testonly.DemoPrivateKeyPass),
		}),
		PublicKey: &keyspb.PublicKey{
			Der: ktestonly.MustMarshalPublicPEMToDER(testonly.DemoPublicKey),
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	var err error
	ctx := context.Background()
	logconn, err = grpc.Dial(mapServer, grpc.WithInsecure())
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
	fmt.Printf("tree ID is %d\n", treeId)
	vlog = trillian.NewTrillianLogClient(logconn)
	_, err = vlog.InitLog(ctx, &trillian.InitLogRequest{
		LogId: treeId,
	})
	if err != nil {
		panic(err)
	}
	logId = treeId
}

func addToLog(value []byte) int64 {
	ctx := context.Background()
	llf := &trillian.LogLeaf{
		LeafValue: value,
	}
	resp, err := vlog.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: logId,
		Leaf:  llf,
	})
	if err != nil {
		panic(err)
	}
	return resp.QueuedLeaf.Leaf.LeafIndex
}

func main() {
	initlog()
	fmt.Printf("index 1: %d\n", addToLog([]byte("hellop1")))
	fmt.Printf("index 2: %d\n", addToLog([]byte("hellop12")))
}
