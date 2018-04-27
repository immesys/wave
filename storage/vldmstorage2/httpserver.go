package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

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
	http.Handle("/", r)
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}
