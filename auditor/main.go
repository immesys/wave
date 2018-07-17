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
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle/hashers"
	_ "github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"github.com/gorilla/pat"
	"github.com/immesys/wave/storage/simplehttp"
	"github.com/immesys/wave/storage/vldmstorage2/pb"
	"google.golang.org/grpc"
)

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

var signatures map[string]bool
var sigmu sync.Mutex

type Config struct {
	Target         string
	PublicKey      string
	Output         string
	Peers          []string
	PeerListenPort int
}

var conf *Config
var ofile *os.File

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: ./auditor <config.toml>\n")
		os.Exit(1)
	}
	cfg, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("couldn't read config: %v\n", err)
		os.Exit(1)
	}
	if _, err := toml.Decode(string(cfg), &conf); err != nil {
		fmt.Printf("couldn't read config: %v\n", err)
		os.Exit(1)
	}
	ofile, err = os.Create(conf.Output)
	if err != nil {
		fmt.Printf("could not open output file: %v\n", err)
		os.Exit(1)
	}
	initmap()
	signatures = make(map[string]bool)
	pubk, _ := pem.Decode([]byte(conf.PublicKey))
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
	if oplogSTH == nil || maplogSTH == nil {
		fmt.Printf("could not get initial STHs\n")
		os.Exit(1)
	}
	go StartHTTP()
	for {
		time.Sleep(10 * time.Second)
		newOpLogSTH := getLogSTH("oplog")
		if newOpLogSTH == nil || newOpLogSTH.TreeSize <= oplogSTH.TreeSize {
			continue
		}
		newMapLogSTH := getLogSTH("rootlog")
		if newMapLogSTH == nil {
			continue
		}
		if maplogSTH.TreeSize != 0 {
			auditLog("oplog", oplogSTH, newOpLogSTH)
			auditLog("rootlog", maplogSTH, newMapLogSTH)
			verifyMap()
		}
		oplogSTH = newOpLogSTH
		maplogSTH = newMapLogSTH
		sigmu.Lock()
		signatures[string(maplogSTH.LogRootSignature)] = true
		sigmu.Unlock()
		gossip(maplogSTH)
	}
}

func gossip(sth *trillian.SignedLogRoot) {
	ba, err := proto.Marshal(sth)
	if err != nil {
		panic(err)
	}
	for _, peer := range conf.Peers {
		b := bytes.NewBuffer(ba)
		req, err := http.NewRequest("POST", peer+"/v1/sth", b)
		if err != nil {
			panic(err)
		}

		ctx, cancel := context.WithTimeout(req.Context(), 500*time.Millisecond)
		defer cancel()

		req = req.WithContext(ctx)

		client := http.DefaultClient
		_, err = client.Do(req)
		if err != nil {
			fmt.Printf("PEER ERROR %v\n", err)
		}
	}
}
func get(suffix string) ([]byte, bool) {
	response, err := http.Get(conf.Target + suffix)
	if err != nil {
		fmt.Printf("got HTTP error: %v\n", err)
		return nil, false
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	if response.StatusCode != 200 {
		fmt.Printf("got non 200: %v\n", string(contents))
		return nil, false
	}
	return contents, true
}
func getLogSTH(log string) *trillian.SignedLogRoot {
	ba, ok := get("/audit/" + log + "/sth")
	if !ok {
		return nil
	}
	smr := &trillian.SignedLogRoot{}
	err := proto.Unmarshal(ba, smr)
	if err != nil {
		fmt.Printf("ba was %q\n", ba)
		panic(err)
	}
	return smr
}
func auditLog(log string, from *trillian.SignedLogRoot, to *trillian.SignedLogRoot) bool {
	ba, ok := get(fmt.Sprintf("/audit/"+log+"/consistency?from=%d&to=%d", from.TreeSize, to.TreeSize))
	if !ok {
		report("log failed to answer HTTP request")
	}
	proof := &trillian.Proof{}
	err := proto.Unmarshal(ba, proof)
	if err != nil {
		report("invalid consistency proof (unmarshal)", ba)
	}
	lrv1 := &types.LogRootV1{}
	err = lrv1.UnmarshalBinary(from.LogRoot)
	if err != nil {
		report("invalid consistency proof (logroot)", ba)
	}
	_, err = logverifier.VerifyRoot(lrv1, to, proof.Hashes)
	if err != nil {
		report("root failed to verify", ba)
	}
	return true
}

type PromiseObject struct {
	Promise *simplehttp.MergePromise
	Key     []byte
	Value   []byte
}

func report(msg string, proof ...[]byte) {
	ofile.Write([]byte(fmt.Sprintf("ERROR %s: %s\n", time.Now().Format(time.RFC3339), msg)))
	for idx, p := range proof {
		ofile.Write([]byte(fmt.Sprintf(" %d: %x\n", idx, p)))
	}
}
func StartHTTP() {
	r := pat.New()
	r.Post("/v1/sth", PeerSTHHandler)
	http.Handle("/", r)
	err := http.ListenAndServe(fmt.Sprintf(":%d", conf.PeerListenPort), nil)
	panic(err)
}

func PeerSTHHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ba, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}

	slr := &trillian.SignedLogRoot{}
	err = proto.Unmarshal(ba, slr)
	if err != nil {
		fmt.Printf("peer unmarshal error\n")
		return
	}

	sigmu.Lock()
	seen := signatures[string(slr.LogRootSignature)]
	sigmu.Unlock()
	if seen {
		fmt.Printf("peer sent STH we have seen\n")
		return
	}
	//Verify it to make sure its the same key
	_, err = tcrypto.VerifySignedLogRoot(logverifier.PubKey, logverifier.SigHash, slr)
	if err != nil {
		fmt.Printf("peer sent bad log root\n")
		return
	}
	//Get inclusion proof for this root
	curSTH := maplogSTH
	if slr.TreeSize < curSTH.TreeSize {
		fmt.Printf("peer STH is before ours\n")
		auditLog("rootlog", slr, curSTH)
	} else if slr.TreeSize > curSTH.TreeSize {
		fmt.Printf("peer STH is after ours\n")
		auditLog("rootlog", curSTH, slr)
		sigmu.Lock()
		signatures[string(slr.LogRootSignature)] = true
		sigmu.Unlock()
	} else {
		current, _ := proto.Marshal(curSTH)
		report("Two STH's found with the same tree size", ba, current)
	}
}

func verifyMap() {
	//get the map root
	for {
		if maprootindex >= maplogSTH.TreeSize {
			return
		}
		ba, ok := get(fmt.Sprintf("/audit/rootlog/item?index=%d&size=%d", maprootindex, maplogSTH.TreeSize))
		if !ok {
			report("log failed to answer item query")
			return
		}
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
		mrv1 := &types.MapRootV1{}
		err = mrv1.UnmarshalBinary(smr.MapRoot)
		if err != nil {
			panic(err)
		}
		mapperMetadata := &pb.MapperMetadata{}
		if err := proto.Unmarshal(mrv1.Metadata, mapperMetadata); err != nil {
			panic(err)
		}
		ops := []*trillian.MapLeaf{}
		for i := currentMapOpLogIndex; i <= mapperMetadata.HighestFullyCompletedSeq; i++ {
			ba, ok := get(fmt.Sprintf("/audit/oplog/item?index=%d&size=%d", i, oplogSTH.TreeSize))
			if !ok {
				report("log failed to answer item query")
				return
			}
			rsp := &trillian.GetEntryAndProofResponse{}
			err := proto.Unmarshal(ba, rsp)
			if err != nil {
				report("object failed to unmarshal", ba)
			}
			lrv1 := &types.LogRootV1{}
			err = lrv1.UnmarshalBinary(oplogSTH.LogRoot)
			if err != nil {
				panic(err)
			}

			err = logverifier.VerifyInclusionAtIndex(lrv1, rsp.Leaf.LeafValue, rsp.Leaf.LeafIndex, rsp.Proof.Hashes)
			if err != nil {
				report("inclusion proof failed to validate", ba)
				return
			}
			mp := &PromiseObject{}
			err = json.Unmarshal(rsp.Leaf.LeafValue, &mp)
			if err != nil {
				report("object failed to unmarshal", ba)
			}
			ops = append(ops, &trillian.MapLeaf{
				Index:     mp.Key,
				LeafValue: mp.Value,
			})
		}
		currentMapOpLogIndex = mapperMetadata.HighestFullyCompletedSeq + 1
		req := &trillian.SetMapLeavesRequest{
			MapId:    mapId,
			Leaves:   ops,
			Metadata: mrv1.Metadata,
		}
		resp, err := vmap.SetLeaves(context.Background(), req)
		if err != nil {
			panic(err)
		}
		replicamaproot := &types.MapRootV1{}
		err = replicamaproot.UnmarshalBinary(resp.MapRoot.MapRoot)
		if err != nil {
			panic(err)
		}
		if bytes.Equal(replicamaproot.RootHash, mrv1.RootHash) {
			fmt.Printf("MAP ROOT %d VALIDATED SUCCESSFULLY\n", maprootindex)
			maprootindex++
		} else {
			report("map root failed to validate", ba)
		}
	}
}
