package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
)

const logServer = "localhost:8092"
const mapServer = "localhost:8090"

var PublicKey string
var PrivateKey string
var PrivateKeyUnpacked *ecdsa.PrivateKey
var TreeID_Op int64
var TreeID_Map int64

type PromiseObject struct {
	Promise *simplehttp.MergePromise
	Seals   []*simplehttp.V1AuditorSig
	Key     []byte
	Value   []byte
}

var promisemu sync.Mutex
var promises map[string]*PromiseObject

func initstorage() {
	optreeid := os.Getenv("VLDM_TREE_OPERATIONS")
	maptreeid := os.Getenv("VLDM_TREE_MAP")

	if optreeid == "" || maptreeid == "" {
		fmt.Printf("Missing tree ids\n")
		os.Exit(1)
	}

	v, err := strconv.ParseInt(optreeid, 10, 64)
	if err != nil {
		fmt.Printf("could not parse tree id:%v\n", err)
	}
	TreeID_Op = v

	v, err = strconv.ParseInt(maptreeid, 10, 64)
	if err != nil {
		fmt.Printf("could not parse tree id:%v\n", err)
	}
	TreeID_Map = v

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
	pk, err := ParsePrivateKey(priv)
	if err != nil {
		fmt.Printf("could not parse private key\n", err)
	}
	PrivateKeyUnpacked = pk
	queueindexes = make(map[string]int64)
	promises = make(map[string]*PromiseObject)
}

type GetMapKeyResponse struct {
	Unmerged bool
	Seal     *simplehttp.V1AuditorSig
	//If unmerged
	MergePromise *simplehttp.MergePromise
	//If merged
	SignedMapRoot []byte
	MapInclusion  []byte
	SignedLogRoot []byte
	LogInclusion  []byte
	Value         []byte
}

//
// func GetMapKeyAtRev(key []byte, rev int64) (bool, *GetMapKeyResponse) {
// 	resp2, err := vmap.GetLeavesByRevision(context.Background(), &trillian.GetMapLeavesByRevisionRequest{
// 		MapId:    TreeID_Map,
// 		Index:    [][]byte{key},
// 		Revision: rev,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	if resp2.MapLeafInclusion[0].Leaf.LeafValue == nil {
// 		//check for promise rather
// 		promisemu.Lock()
// 		pv, ok := promises[string(key)]
// 		promisemu.Unlock()
// 		if ok {
// 			return true, &GetMapKeyResponse{
// 				Unmerged:     true,
// 				MergePromise: pv.Promise,
// 				Value:        pv.Value,
// 			}
// 		}
// 	}
//
// 	smrbytes, err := proto.Marshal(resp2.MapRoot)
// 	if err != nil {
// 		panic(err)
// 	}
// 	h := sha256.New()
// 	h.Write([]byte{0})
// 	h.Write(smrbytes)
// 	r := h.Sum(nil)
// 	_ = r
//
// 	inclusion, err := proto.Marshal(resp2.MapLeafInclusion[0])
// 	if err != nil {
// 		panic(err)
// 	}
// 	smr, err := proto.Marshal(resp2.MapRoot)
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	if resp2.MapLeafInclusion[0].Leaf.LeafValue == nil {
// 		return true, &GetMapKeyResponse{
// 			SignedMapRoot: smr,
// 			MapInclusion:  inclusion,
// 		}
// 	} else {
// 		// pv := &PromiseObject{}
// 		// fmt.Printf("leaf value is: %q", resp2.MapLeafInclusion[0].Leaf.LeafValue)
// 		// err := json.Unmarshal(resp2.MapLeafInclusion[0].Leaf.LeafValue, pv)
// 		// if err != nil {
// 		// 	panic(err)
// 		// }
// 		return true, &GetMapKeyResponse{
// 			SignedMapRoot: smr,
// 			MapInclusion:  inclusion,
// 			Value:         resp2.MapLeafInclusion[0].Leaf.LeafValue,
// 		}
// 	}
// }

var goodrev int64

func MapSigTooOld(v *dbSMR) bool {
	return time.Unix(0, v.Timestamp*1e6).Before(time.Now().Add(-1 * time.Hour))
}
func GetPromise(identities []string, key []byte) *PromiseObject {
	//TODO if promise object is lacking a signature by the given identities
	//then go get another signature on it
	promisemu.Lock()
	p := promises[string(key)]
	promisemu.Unlock()
	return p
}

var ErrMapRootTooOld = errors.New("No recent map roots audited by the given ids found")

func GetMapKeyValue(identities []string, key []byte) (*GetMapKeyResponse, error) {
	dbSMR, err := DB.GetLatestMapRootSignature(identities)
	if err != nil {
		return nil, err
	}

	checkPromise := func() *GetMapKeyResponse {
		pv := GetPromise(identities, key)
		if pv != nil {
			return &GetMapKeyResponse{
				Seal:         pv.Seals[0],
				Unmerged:     true,
				MergePromise: pv.Promise,
				Value:        pv.Value,
			}
		}
		fmt.Printf("promise is nil\n")
		return nil
	}

	if dbSMR == nil {
		p := checkPromise()
		if p == nil {
			return nil, ErrMapRootTooOld
		}
		return p, nil
	}

	if MapSigTooOld(dbSMR) {
		return nil, ErrMapRootTooOld
	}
	resp2, err := vmap.GetLeavesByRevision(context.Background(), &trillian.GetMapLeavesByRevisionRequest{
		MapId:    TreeID_Map,
		Index:    [][]byte{key},
		Revision: int64(dbSMR.Revision),
	})
	if err != nil {
		panic(err)
	}
	if resp2.MapLeafInclusion[0].Leaf.LeafValue == nil {
		//check for promise rather
		p := checkPromise()
		if p != nil {
			return p, nil
		}
	}

	smrbytes, err := proto.Marshal(resp2.MapRoot)
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(smrbytes)
	r := h.Sum(nil)
	_ = r
	inclusion, err := proto.Marshal(resp2.MapLeafInclusion[0])
	if err != nil {
		panic(err)
	}
	smr, err := proto.Marshal(resp2.MapRoot)
	if err != nil {
		panic(err)
	}

	if resp2.MapLeafInclusion[0].Leaf.LeafValue == nil {
		return &GetMapKeyResponse{
			SignedMapRoot: smr,
			MapInclusion:  inclusion,
			Seal: &simplehttp.V1AuditorSig{
				Timestamp: dbSMR.Timestamp,
				Identity:  dbSMR.SigIdentity,
				SigR:      dbSMR.R,
				SigS:      dbSMR.S,
			},
		}, nil
	} else {
		// pv := &PromiseObject{}
		// fmt.Printf("leaf value is: %q", resp2.MapLeafInclusion[0].Leaf.LeafValue)
		// err := json.Unmarshal(resp2.MapLeafInclusion[0].Leaf.LeafValue, pv)
		// if err != nil {
		// 	panic(err)
		// }
		return &GetMapKeyResponse{
			SignedMapRoot: smr,
			MapInclusion:  inclusion,
			Value:         resp2.MapLeafInclusion[0].Leaf.LeafValue,
			Seal: &simplehttp.V1AuditorSig{
				Timestamp: dbSMR.Timestamp,
				Identity:  dbSMR.SigIdentity,
				SigR:      dbSMR.R,
				SigS:      dbSMR.S,
			},
		}, nil
	}
}

func InsertKeyValue(identities []string, key []byte, value []byte) (*simplehttp.MergePromise, *simplehttp.V1AuditorSig, error) {
	//TODO check for existing merge promise for this value
	hi := iapi.KECCAK256.Instance(value)
	hasharr := hi.Value()
	mp, asig, err := MakeMergePromise(key, hasharr, identities, PrivateKeyUnpacked)
	if err != nil {
		return nil, nil, err
	}
	po := &PromiseObject{
		Promise: mp,
		Seals:   []*simplehttp.V1AuditorSig{asig},
		Key:     key,
		Value:   value,
	}
	promisemu.Lock()
	promises[string(key)] = po
	promisemu.Unlock()
	poj, err := json.Marshal(po)
	if err != nil {
		fmt.Printf("failed to marshal promise object: %v\n", err)
	}
	ctx := context.Background()
	llf := &trillian.LogLeaf{
		LeafValue: poj,
	}
	_, err = logclient.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: TreeID_Op,
		Leaf:  llf,
	})
	if err != nil {
		panic(err)
	}
	return mp, asig, nil
}

func Exists(queueid []byte, index int64) bool {
	tohash := make([]byte, 40)
	copy(tohash[:32], queueid)
	binary.LittleEndian.PutUint64(tohash[32:], uint64(index+1))
	hi := iapi.KECCAK256.Instance(tohash)
	hiarr := hi.Value()

	resp2, err := vmap.GetLeaves(context.Background(), &trillian.GetMapLeavesRequest{
		MapId: TreeID_Map,
		Index: [][]byte{hiarr},
	})
	if err != nil {
		panic(err)
	}
	return resp2.MapLeafInclusion[0].Leaf.LeafValue != nil
}

var queueindexes map[string]int64
var queuemu sync.Mutex

func GetIndex(queueid []byte) int64 {
	queuemu.Lock()
	idx, ok := queueindexes[string(queueid)]
	queuemu.Unlock()
	if ok {
		return idx
	}
	if !Exists(queueid, 0) {
		return -1
	}
	start := int64(128)
	for Exists(queueid, start) {
		start <<= 4
	}
	pivot := start / 2
	interval := start / 4
	for {
		if Exists(queueid, pivot) {
			if interval == 0 {
				break
			}
			pivot += interval
			interval /= 2
		} else {
			if interval == 0 {
				pivot--
				break
			}
			pivot -= interval
			interval /= 2
		}
	}
	queuemu.Lock()
	queueindexes[string(queueid)] = pivot
	queuemu.Unlock()
	return pivot
}
func SetIndex(queueid []byte, id int64) {
	queuemu.Lock()
	queueindexes[string(queueid)] = id
	queuemu.Unlock()
}
