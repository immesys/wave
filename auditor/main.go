//https://gist.github.com/whyrusleeping/169a28cffe1aedd4419d80aa62d361aa
package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle/hashers"
	_ "github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"github.com/immesys/wave/storage/simplehttp"
	"github.com/immesys/wave/storage/vldmstorage2/pb"
	"google.golang.org/grpc"
)

const location = "http://127.0.0.1:8080/v1"
const PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWs0VFmqFr27SeEw4DttPmglDhqMj
KNzHzySfKQi6/IE4AlBvPlJOqEawPXVr3gJlk8SWlt3Ts9MEWFaLKc4lAQ==
-----END PUBLIC KEY-----`

var logverifier *client.LogVerifier

const mapServer = "localhost:8090"

var MapTree *trillian.Tree
var mapconn *grpc.ClientConn
var vmap trillian.TrillianMapClient
var mapId int64
var currentMapOpLogIndex int64

const OurPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmTz0jNtdPnob3U8uylM5PORUJPw2
9VEU8V68V8FtlxFxuuU6MFHzN5/3XnWCeJ0xJ1Uabk1r/eS0H7aWOksMNA==
-----END PUBLIC KEY-----`

const OurPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaK0u/I9YXTE7Yxb6
uGK3vX/KzWQVqCpqctv4hhAWEcuhRANCAASZPPSM210+ehvdTy7KUzk85FQk/Db1
URTxXrxXwW2XEXG65TowUfM3n/dedYJ4nTEnVRpuTWv95LQftpY6Sww0
-----END PRIVATE KEY-----`

func mustMarshalAny(pb proto.Message) *any.Any {
	value, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err)
	}
	return value
}

func initmap() {
	pubk, _ := pem.Decode([]byte(OurPublicKey))
	privk, _ := pem.Decode([]byte(OurPrivateKey))
	var err error
	MapTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
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
	vmap = trillian.NewTrillianMapClient(mapconn)
	_, err = vmap.InitMap(ctx, &trillian.InitMapRequest{
		MapId: mapId,
	})
	if err != nil {
		panic(err)
	}
	currentMapOpLogIndex = 0
	maprootindex = 0
}

var maprootindex int64
var oplogSTH *trillian.SignedLogRoot
var maplogSTH *trillian.SignedLogRoot

func main() {
	initmap()
	pubk, _ := pem.Decode([]byte(PublicKey))
	pubkobj, err := der.UnmarshalPublicKey(pubk.Bytes)
	if err != nil {
		panic(err)
	}
	hasher, err := hashers.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		panic(err)
	}
	logverifier = client.NewLogVerifier(hasher, pubkobj, crypto.SHA256)
	oplogSTH = getLogSTH("oplog")
	maplogSTH = getLogSTH("rootlog")

	for {
		time.Sleep(10 * time.Second)
		newOpLogSTH := getLogSTH("oplog")
		if newOpLogSTH.TreeSize <= oplogSTH.TreeSize {
			continue
		}
		newMapLogSTH := getLogSTH("rootlog")
		auditLog("oplog", oplogSTH, newOpLogSTH)
		auditLog("rootlog", maplogSTH, newMapLogSTH)
		verifyMap()
		oplogSTH = newOpLogSTH
		maplogSTH = newMapLogSTH
	}
}

func get(suffix string) []byte {
	response, err := http.Get(location + suffix)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	if response.StatusCode != 200 {
		fmt.Printf("got non 200: %v\n", string(contents))
		panic("abort")
	}
	return contents
}
func getLogSTH(log string) *trillian.SignedLogRoot {
	ba := get("/audit/" + log + "/sth")
	smr := &trillian.SignedLogRoot{}
	err := proto.Unmarshal(ba, smr)
	if err != nil {
		fmt.Printf("ba was %q\n", ba)
		panic(err)
	}
	return smr
}
func auditLog(log string, from *trillian.SignedLogRoot, to *trillian.SignedLogRoot) bool {
	ba := get(fmt.Sprintf("/audit/"+log+"/consistency?from=%d&to=%d", from.TreeSize, to.TreeSize))
	proof := &trillian.Proof{}
	err := proto.Unmarshal(ba, proof)
	if err != nil {
		panic(err)
	}
	lrv1 := &types.LogRootV1{}
	err = lrv1.UnmarshalBinary(from.LogRoot)
	if err != nil {
		panic(err)
	}
	_, err = logverifier.VerifyRoot(lrv1, to, proof.Hashes)
	if err != nil {
		panic(err)
	}
	return true
}

type PromiseObject struct {
	Promise *simplehttp.MergePromise
	Key     []byte
	Value   []byte
}

func verifyMap() {
	//get the map root
	for {
		if maprootindex >= maplogSTH.TreeSize {
			return
		}
		ba := get(fmt.Sprintf("/audit/rootlog/item?index=%d&size=%d", maprootindex, maplogSTH.TreeSize))
		ger := &trillian.GetEntryAndProofResponse{}
		err := proto.Unmarshal(ba, ger)
		//TODO check proof
		if err != nil {
			panic(err)
		}
		smr := &trillian.SignedMapRoot{}
		err = proto.Unmarshal(ger.Leaf.LeafValue, smr)
		if err != nil {
			panic(err)
		}
		spew.Dump(smr)
		mrv1 := &types.MapRootV1{}
		err = mrv1.UnmarshalBinary(smr.MapRoot)
		if err != nil {
			panic(err)
		}
		fmt.Printf("target map of size %d has hash %x\n", mrv1.Revision, mrv1.RootHash)
		mapperMetadata := &pb.MapperMetadata{}
		if err := proto.Unmarshal(mrv1.Metadata, mapperMetadata); err != nil {
			panic(err)
		}
		ops := []*trillian.MapLeaf{}
		for i := currentMapOpLogIndex; i <= mapperMetadata.HighestFullyCompletedSeq; i++ {
			fmt.Printf("getting index %d\n", i)
			ba := get(fmt.Sprintf("/audit/oplog/item?index=%d&size=%d", i, oplogSTH.TreeSize))
			rsp := &trillian.GetEntryAndProofResponse{}
			err := proto.Unmarshal(ba, rsp)
			if err != nil {
				panic(err)
			}
			lrv1 := &types.LogRootV1{}
			err = lrv1.UnmarshalBinary(oplogSTH.LogRoot)
			if err != nil {
				panic(err)
			}

			err = logverifier.VerifyInclusionAtIndex(lrv1, rsp.Leaf.LeafValue, rsp.Leaf.LeafIndex, rsp.Proof.Hashes)
			if err != nil {
				panic(err)
			}
			mp := &PromiseObject{}
			err = json.Unmarshal(rsp.Leaf.LeafValue, &mp)
			if err != nil {
				panic(err)
			}
			ops = append(ops, &trillian.MapLeaf{
				Index:     mp.Key,
				LeafValue: mp.Value,
			})
		}
		currentMapOpLogIndex = mapperMetadata.HighestFullyCompletedSeq + 1
		fmt.Printf("appling %d operations\n", len(ops))
		req := &trillian.SetMapLeavesRequest{
			MapId:    mapId,
			Leaves:   ops,
			Metadata: mrv1.Metadata,
		}
		spew.Dump(req)
		resp, err := vmap.SetLeaves(context.Background(), req)
		if err != nil {
			panic(err)
		}
		replicamaproot := &types.MapRootV1{}
		err = replicamaproot.UnmarshalBinary(resp.MapRoot.MapRoot)
		if err != nil {
			panic(err)
		}
		fmt.Printf("our map of size %d has hash %x\n", replicamaproot.Revision, replicamaproot.RootHash)
		if bytes.Equal(replicamaproot.RootHash, mrv1.RootHash) {
			fmt.Printf("MAP ROOT VALIDATED SUCCESSFULLY\n")
			maprootindex++
		} else {
			fmt.Printf("MAP ROOT FAILED TO VALIDATE\n")
			os.Exit(1)
		}
	}
}
