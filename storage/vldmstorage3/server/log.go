package main

import (
	"encoding/pem"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	"google.golang.org/grpc"
)

func mustMarshalAny(pb proto.Message) *any.Any {
	value, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err)
	}
	return value
}

var logconn *grpc.ClientConn
var OpLogTree *trillian.Tree
var RootLogTree *trillian.Tree
var logclient trillian.TrillianLogClient
var logId int64
var logverifier *client.LogVerifier

func initlogs() {
	pubk, _ := pem.Decode([]byte(PublicKey))
	privk, _ := pem.Decode([]byte(PrivateKey))
	OpLogTree = &trillian.Tree{
		TreeId:             TreeID_Op,
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "OPERATIONS",
		Description:        "for WAVE",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: privk.Bytes,
		}),
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	RootLogTree = &trillian.Tree{
		TreeId:             TreeID_Root,
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "ROOT",
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
	logconn, err = grpc.Dial(logServer, grpc.WithInsecure())
	if err != nil {
		glog.Fatal(err)
	}
	logclient = trillian.NewTrillianLogClient(logconn)
	logverifier, err = client.NewLogVerifierFromTree(RootLogTree)
	if err != nil {
		panic(err)
	}
}

// func addToLog(value []byte) int64 {
// 	ctx := context.Background()
// 	llf := &trillian.LogLeaf{
// 		LeafValue: value,
// 	}
// 	resp, err := vlog.QueueLeaf(ctx, &trillian.QueueLeafRequest{
// 		LogId: logId,
// 		Leaf:  llf,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	return resp.QueuedLeaf.Leaf.LeafIndex
// }
