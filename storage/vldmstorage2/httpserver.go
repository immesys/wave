package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/gorilla/pat"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
	multihash "github.com/multiformats/go-multihash"
)

const VersionBanner = "VLDM 0.0.2"

func GetHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get(":hash")
	r.Body.Close()
	hashbin, err := base64.URLEncoding.DecodeString(hash)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("{}"))
		return
	}
	mh, err := multihash.Decode(hashbin)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("{}"))
		return
	}
	mkr := GetMapKeyValue(mh.Digest)
	if mkr.Value == nil {
		w.WriteHeader(404)
		rv := simplehttp.ObjectResponse{
			V1SMR:          mkr.SignedMapRoot,
			V1MapInclusion: mkr.MapInclusion,
		}
		json.NewEncoder(w).Encode(&rv)
		return
	}
	if mkr.Unmerged {
		w.WriteHeader(200)
		rv := simplehttp.ObjectResponse{
			DER:            mkr.Value,
			V1MergePromise: mkr.MergePromise,
		}
		json.NewEncoder(w).Encode(&rv)
		return
	}
	rv := simplehttp.ObjectResponse{
		DER:            mkr.Value,
		V1SMR:          mkr.SignedMapRoot,
		V1MapInclusion: mkr.MapInclusion,
	}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&rv)
}
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	r.Body.Close()
	rv := simplehttp.InfoResponse{
		HashScheme: iapi.KECCAK256.OID().String(),
		Version:    VersionBanner,
	}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&rv)
}
func PutHandler(w http.ResponseWriter, r *http.Request) {
	params := simplehttp.PutObjectRequest{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	r.Body.Close()
	hash := iapi.KECCAK256.Instance(params.DER)
	promise := InsertKeyValue(hash.Value(), params.DER)
	// smr, mli := addToMap(hash.Value(), params.DER)
	// inclusionb, err := proto.Marshal(mli)
	// if err != nil {
	// 	panic(err)
	// }
	// smrb, err := proto.Marshal(smr)
	// if err != nil {
	// 	panic(err)
	// }
	resp := simplehttp.PutObjectResponse{
		Hash:           hash.Multihash(),
		V1MergePromise: promise,
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(&resp)
}
func IterateHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	id := r.URL.Query().Get(":id")
	var index64 int64
	var err error
	if token == "" {
		index64 = 0
	} else {
		index64, err = strconv.ParseInt(token, 10, 64)
		if err != nil {
			//fmt.Printf("ITER with unparseable token\n")
			w.WriteHeader(404)
			w.Write([]byte("{}"))
			return
		}
	}
	index := int(index64)
	idb, err := base64.URLEncoding.DecodeString(id)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad id hash"))
		return
	}
	idmh, err := multihash.Decode(idb)
	if err != nil || idmh.Code != multihash.KECCAK_256 {
		w.WriteHeader(400)
		w.Write([]byte("bad hash"))
		return
	}
	tohash := make([]byte, 40)
	copy(tohash[:32], idmh.Digest)
	binary.LittleEndian.PutUint64(tohash[32:], uint64(index))
	hi := iapi.KECCAK256.Instance(tohash)
	hiarr := hi.Value()
	mkr := GetMapKeyValue(hiarr)
	if mkr.Value == nil {
		w.WriteHeader(404)
		rv := simplehttp.IterateQueueResponse{
			V1SMR:          mkr.SignedMapRoot,
			V1MapInclusion: mkr.MapInclusion,
		}
		json.NewEncoder(w).Encode(&rv)
		return
	}
	if mkr.Unmerged {
		w.WriteHeader(200)
		rv := simplehttp.IterateQueueResponse{
			Hash:           mkr.Value,
			NextToken:      fmt.Sprintf("%d", index+1),
			V1MergePromise: mkr.MergePromise,
		}
		json.NewEncoder(w).Encode(&rv)
		return
	}
	rv := simplehttp.IterateQueueResponse{
		Hash:           mkr.Value,
		NextToken:      fmt.Sprintf("%d", index+1),
		V1SMR:          mkr.SignedMapRoot,
		V1MapInclusion: mkr.MapInclusion,
	}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&rv)
	return
}
func EnqueueHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get(":id")
	req := simplehttp.EnqueueRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	r.Body.Close()
	entrymulti, err := multihash.Decode(req.EntryHash)
	if err != nil || entrymulti.Code != multihash.KECCAK_256 {
		w.WriteHeader(400)
		w.Write([]byte("bad hash"))
		return
	}
	idb, err := base64.URLEncoding.DecodeString(id)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad id hash"))
		return
	}
	idmh, err := multihash.Decode(idb)
	if err != nil || entrymulti.Code != multihash.KECCAK_256 {
		w.WriteHeader(400)
		w.Write([]byte("bad hash"))
		return
	}

	index := GetIndex(idmh.Digest)
	tohash := make([]byte, 40)
	copy(tohash[:32], idmh.Digest)
	binary.LittleEndian.PutUint64(tohash[32:], uint64(index+1))

	hi := iapi.KECCAK256.Instance(tohash)
	hiarr := hi.Value()

	promise := InsertKeyValue(hiarr, req.EntryHash)

	SetIndex(idmh.Digest, index+1)
	w.WriteHeader(201)
	resp := simplehttp.EnqueueResponse{
		V1MergePromise: promise,
	}
	json.NewEncoder(w).Encode(&resp)
	return
}
func main() {
	initstorage()
	initlogs()
	initmap()
	go startMappingLoops()
	//db = make(map[string][]byte)
	//queues = make(map[string]int)
	r := pat.New()
	r.Post("/v1/obj", PutHandler)
	r.Get("/v1/info", InfoHandler)
	r.Get("/v1/obj/{hash}", GetHandler)
	r.Get("/v1/queue/{id}", IterateHandler)
	r.Post("/v1/queue/{id}", EnqueueHandler)
	r.Get("/v1/audit/oplog/consistency", OplogConsistencyHandler)
	r.Get("/v1/audit/rootlog/consistency", RootlogConsistencyHandler)
	r.Get("/v1/audit/oplog/sth", OplogSTHHandler)
	r.Get("/v1/audit/rootlog/sth", RootlogSTHHandler)
	r.Get("/v1/audit/oplog/item", OplogItemHandler)
	r.Get("/v1/audit/rootlog/item", RootlogItemHandler)
	//get("/audit/" + log + "/sth")
	// get(fmt.Sprintf("/audit/"+log+"/consistency?from=%d&to=%d", from.TreeSize, to.TreeSize))
	// ba := get(fmt.Sprintf("/audit/rootlog/item?index=%d", maprootindex))
	// ba := get(fmt.Sprintf("/audit/oplog/item?index=%d&size=%d", i, oplogSTH.TreeSize))

	http.Handle("/", r)
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}

func OplogSTHHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got Oplog STH handler\n")
	logSTH(TreeID_Op, w, r)
}
func RootlogSTHHandler(w http.ResponseWriter, r *http.Request) {
	logSTH(TreeID_Root, w, r)
}
func logSTH(logid int64, w http.ResponseWriter, r *http.Request) {
	resp, err := logclient.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
		LogId: logid,
	})
	if err != nil {
		panic(err)
	}
	ba, err := proto.Marshal(resp.SignedLogRoot)
	if err != nil {
		panic(err)
	}
	w.WriteHeader(200)
	w.Write(ba)
}
func OplogConsistencyHandler(w http.ResponseWriter, r *http.Request) {
	logConsistencyHandler(TreeID_Op, w, r)
}
func RootlogConsistencyHandler(w http.ResponseWriter, r *http.Request) {
	logConsistencyHandler(TreeID_Root, w, r)
}
func OplogItemHandler(w http.ResponseWriter, r *http.Request) {
	logItemHandler(TreeID_Op, w, r)
}
func RootlogItemHandler(w http.ResponseWriter, r *http.Request) {
	logItemHandler(TreeID_Root, w, r)
}
func logConsistencyHandler(logid int64, w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	fromi, err := strconv.ParseInt(from, 10, 64)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad 'from' parameter"))
		return
	}
	toi, err := strconv.ParseInt(to, 10, 64)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad 'to' parameter"))
		return
	}
	resp, err := logclient.GetConsistencyProof(context.Background(), &trillian.GetConsistencyProofRequest{
		LogId:          logid,
		FirstTreeSize:  fromi,
		SecondTreeSize: toi,
	})
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(200)
	ba, err := proto.Marshal(resp.Proof)
	if err != nil {
		panic(err)
	}
	w.Write(ba)
	return
}
func logItemHandler(logid int64, w http.ResponseWriter, r *http.Request) {
	index := r.URL.Query().Get("index")
	indexi, err := strconv.ParseInt(index, 10, 64)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad index parameter"))
		return
	}
	size := r.URL.Query().Get("size")
	sizei, err := strconv.ParseInt(size, 10, 64)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad size parameter"))
		return
	}
	resp, err := logclient.GetEntryAndProof(context.Background(), &trillian.GetEntryAndProofRequest{
		LogId:     logid,
		LeafIndex: indexi,
		TreeSize:  sizei,
	})
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	ba, err := proto.Marshal(resp)
	if err != nil {
		panic(err)
	}
	w.Write(ba)
}
