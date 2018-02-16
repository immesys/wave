package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/pat"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
)

var globalmu sync.RWMutex
var db map[string][]byte

type queue struct {
	mu       sync.Mutex
	contents [][]byte
	change   chan struct{}
}

var queues map[string]*queue

func GetHandler(w http.ResponseWriter, r *http.Request) {
	globalmu.RLock()
	defer globalmu.RUnlock()

	hash := r.URL.Query().Get(":hash")
	hash = strings.ToLower(hash)
	r.Body.Close()
	content, ok := db[hash]
	if !ok {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	} else {
		w.Write(content)
	}
}
func PutHandler(w http.ResponseWriter, r *http.Request) {
	globalmu.Lock()
	defer globalmu.Unlock()

	content, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	hash, _ := iapi.KECCAK256.Instance(content)
	hashstring := hex.EncodeToString(hash.Value())
	db[hashstring] = content
	w.Write([]byte(hashstring))
	return
}
func IterateHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get(":token")
	id := r.URL.Query().Get(":id")
	id = strings.ToLower(id)
	if len(id) != 64 {
		w.WriteHeader(400)
		w.Write([]byte("bad hash"))
		return
	}
	var index int64
	var err error
	if token == "" {
		index = 0
	} else {
		index, err = strconv.ParseInt(token, 10, 64)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("bad token"))
			return
		}
	}
	globalmu.Lock()
	q, ok := queues[id]
	if !ok {
		q = &queue{change: make(chan struct{})}
		queues[id] = q
	}
	q.mu.Lock()
	globalmu.Unlock()
	ch := q.change
	//There is something there
	if len(q.contents) > int(index) {
		rv := q.contents[int(index)]
		q.mu.Unlock()
		resp := simplehttp.QueueResponse{
			NextToken: fmt.Sprintf("%d", index+1),
			Content:   rv,
		}
		js, err := json.Marshal(resp)
		if err != nil {
			panic(err)
		}
		w.Write(js)
		return
	}
	q.mu.Unlock()
	shouldWait := r.URL.Query().Get("wait")
	if shouldWait != "1" {
		w.WriteHeader(404)
		return
	}

	//The user asked us to wait (long poll)
	select {
	case <-time.After(30 * time.Second):
	case <-ch:
	}
	q.mu.Lock()
	if len(q.contents) > int(index) {
		rv := q.contents[int(index)]
		q.mu.Unlock()
		resp := simplehttp.QueueResponse{
			NextToken: fmt.Sprintf("%d", index+1),
			Content:   rv,
		}
		js, err := json.Marshal(resp)
		if err != nil {
			panic(err)
		}
		w.Write(js)
		return
	} else {
		q.mu.Unlock()
		w.WriteHeader(404)
		return
	}
}
func EnqueueHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get(":id")
	id = strings.ToLower(id)
	hashbin, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		return
	}
	if len(hashbin) != 32 || len(id) != 64 {
		w.WriteHeader(400)
		w.Write([]byte("bad hash"))
		return
	}
	globalmu.Lock()
	q, ok := queues[id]
	if !ok {
		q = &queue{change: make(chan struct{})}
		queues[id] = q
	}
	q.mu.Lock()
	globalmu.Unlock()
	ch := q.change
	q.change = make(chan struct{})
	q.contents = append(q.contents, hashbin)
	close(ch)
	q.mu.Unlock()
	w.WriteHeader(200)
}
func main() {
	db = make(map[string][]byte)
	queues = make(map[string]*queue)
	r := pat.New()
	r.Post("/obj", PutHandler)
	r.Get("/obj/{hash}", GetHandler)
	r.Get("/queue/{id}/{token}", IterateHandler)
	r.Get("/queue/{id}/", IterateHandler)

	r.Post("/queue/{id}", EnqueueHandler)
	http.Handle("/", r)
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}
