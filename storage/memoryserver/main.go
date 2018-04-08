package memoryserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/pat"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
	multihash "github.com/multiformats/go-multihash"
)

const VersionBanner = "InMem 1.1.0"

var globalmu sync.Mutex
var db map[string][]byte

var queues map[string][][]byte

func GetHandler(w http.ResponseWriter, r *http.Request) {
	globalmu.Lock()
	defer globalmu.Unlock()

	hash := r.URL.Query().Get(":hash")
	r.Body.Close()
	content, ok := db[hash]
	if !ok {
		fmt.Printf("GET missing object\n")
		w.WriteHeader(404)
		w.Write([]byte("{}"))
		return
	}
	rv := simplehttp.ObjectResponse{
		DER: content,
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
	hashstring := hash.MultihashString()
	db[hashstring] = params.DER
	resp := simplehttp.PutObjectResponse{
		Hash: hash.Multihash(),
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
			fmt.Printf("ITER with unparseable token\n")
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
		fmt.Printf("ITER with nonexistant queue\n")
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
	fmt.Printf("ITER with out of bounds in queue\n")
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
