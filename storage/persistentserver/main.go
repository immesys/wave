package persistentserver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/gorilla/pat"
	"github.com/immesys/wave/iapi"
	llsprovider "github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/storage/simplehttp"
	multihash "github.com/multiformats/go-multihash"
	"github.com/urfave/cli"
)

const VersionBanner = "LLS_Persistent 1.1.0"

func GetHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get(":hash")
	r.Body.Close()
	content, err := lls.Load(context.Background(), fmt.Sprintf("obj/%s", hash))
	if err != nil {
		panic(err)
	}
	if content == nil {
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
	err = lls.Store(context.Background(), fmt.Sprintf("obj/%s", hashstring), params.DER)
	if err != nil {
		panic(err)
	}
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
	q, err := lls.Load(context.Background(), fmt.Sprintf("qdata/%s/%d", id, index))
	if err != nil {
		panic(err)
	}
	if q == nil {
		fmt.Printf("ITER with nonexistant queue\n")
		w.WriteHeader(404)
		w.Write([]byte("{}"))
		return
	}

	//There is something there

	resp := simplehttp.IterateQueueResponse{
		NextToken: fmt.Sprintf("%d", index+1),
		Hash:      q,
	}
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&resp)
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
	writemu.Lock()
	headkey := fmt.Sprintf("q/%s/head", id)
	val, err := lls.Load(context.Background(), headkey)
	if err != nil {
		panic(err)
	}
	var idx uint64
	if val == nil {
		idx = 0
	} else {
		idx = binary.LittleEndian.Uint64(val) + 1
	}
	barr := make([]byte, 8)
	binary.LittleEndian.PutUint64(barr, idx)
	err = lls.Store(context.Background(), headkey, barr)
	if err != nil {
		panic(err)
	}
	err = lls.Store(context.Background(), fmt.Sprintf("qdata/%s/%d", id, idx), req.EntryHash)
	if err != nil {
		panic(err)
	}
	writemu.Unlock()
	w.WriteHeader(201)
	w.Write([]byte("{}"))
}
func Main(args []string) {
	app := cli.NewApp()
	app.Name = "pserver"
	app.Usage = "Run a WAVE HTTP v1 persistent storage location"
	app.Action = action
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "port",
			Value: 7000,
		},
		cli.StringFlag{
			Name:  "datadir",
			Value: "./pserver_data",
		},
		cli.StringFlag{
			Name: "certpublic",
		},
		cli.StringFlag{
			Name: "certprivate",
		},
	}
	app.Run(args)
}

var lls iapi.LowLevelStorage
var writemu sync.Mutex

func action(c *cli.Context) error {
	var err error
	lls, err = llsprovider.NewLowLevelStorage(c.String("datadir"))
	if err != nil {
		fmt.Printf("could not initialize the db: %v\n", err)
		os.Exit(1)
	}
	r := pat.New()
	r.Post("/v1/obj", PutHandler)
	r.Get("/v1/info", InfoHandler)
	r.Get("/v1/obj/{hash}", GetHandler)
	r.Get("/v1/queue/{id}", IterateHandler)
	r.Post("/v1/queue/{id}", EnqueueHandler)
	http.Handle("/", r)
	err = http.ListenAndServeTLS(fmt.Sprintf(":%d", c.Int("port")), c.String("certpublic"), c.String("certprivate"), nil)
	panic(err)
}
