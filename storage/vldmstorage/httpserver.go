package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/gorilla/pat"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
	multihash "github.com/multiformats/go-multihash"
)

const VersionBanner = "InMem 1.1.0"

var globalmu sync.Mutex
var db map[string][]byte

var queues map[string]int

func GetHandler(w http.ResponseWriter, r *http.Request) {
	globalmu.Lock()
	defer globalmu.Unlock()

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
	resp2, err := vmap.GetLeaves(context.Background(), &trillian.GetMapLeavesRequest{
		MapId: mapId,
		Index: [][]byte{mh.Digest},
	})
	if err != nil {
		panic(err)
	}
	inclusion, err := proto.Marshal(resp2.MapLeafInclusion[0])
	if err != nil {
		panic(err)
	}
	smr, err := proto.Marshal(resp2.MapRoot)
	if err != nil {
		panic(err)
	}
	rv := simplehttp.ObjectResponse{
		DER:            resp2.MapLeafInclusion[0].Leaf.LeafValue,
		V1SMR:          smr,
		V1MapInclusion: inclusion,
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
	globalmu.Lock()
	defer globalmu.Unlock()

	params := simplehttp.PutObjectRequest{}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	r.Body.Close()
	hash := iapi.KECCAK256.Instance(params.DER)
	smr, mli := addToMap(hash, params.DER)
	inclusionb, err := proto.Marshal(mli)
	if err != nil {
		panic(err)
	}
	smrb, err := proto.Marshal(smr)
	if err != nil {
		panic(err)
	}
	resp := simplehttp.PutObjectResponse{
		Hash:           hash.Multihash(),
		V1MapInclusion: inclusionb,
		V1SMR:          smrb,
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
	globalmu.Lock()
	defer globalmu.Unlock()
	q, ok := queues[id]
	if !ok {
		//fmt.Printf("ITER with nonexistant queue\n")
		w.WriteHeader(404)
		w.Write([]byte("{}"))
		return
	}

	//There is something there
	if len(q) > index {
		rv := q[index]
		resp := simplehttp.IterateQueueResponse{
			NextToken: fmt.Sprintf("%d", index+1),
			Hash:      rv,
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(&resp)
		return
	}
	//fmt.Printf("ITER with out of bounds in queue\n")
	w.WriteHeader(404)
	w.Write([]byte("{}"))
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
	globalmu.Lock()
	qlen := queues[id]
	result := make([]byte, 32)
	binary.LittleEndian.PutUint64(result[0:8], result)
	copy(result[8:], base[8:])
	smr, mli := addToMap(result, req.EntryHash)
	inclusionb, err := proto.Marshal(mli)
	if err != nil {
		panic(err)
	}
	smrb, err := proto.Marshal(smr)
	if err != nil {
		panic(err)
	}

	queues[id] = append(queues[id], req.EntryHash)
	globalmu.Unlock()
	w.WriteHeader(201)
	w.Write([]byte("{}"))
}
func Main() {
	db = make(map[string][]byte)
	queues = make(map[string][][]byte)
	r := pat.New()
	r.Post("/v1/obj", PutHandler)
	r.Get("/v1/info", InfoHandler)
	r.Get("/v1/obj/{hash}", GetHandler)
	r.Get("/v1/queue/{id}", IterateHandler)
	r.Post("/v1/queue/{id}", EnqueueHandler)
	http.Handle("/", r)
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}
