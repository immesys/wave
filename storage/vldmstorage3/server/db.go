package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"github.com/samkumar/reqcache"
)

type db struct {
	db       *sql.DB
	mu       sync.RWMutex
	sigRoots map[string]*dbSMR
	lru      *reqcache.LRUCache
}

var DB *db

func InitDB(connstring string) error {
	h, err := sql.Open("mysql", connstring)
	if err != nil {
		return err
	}
	DB = &db{
		db:       h,
		sigRoots: make(map[string]*dbSMR),
	}

	DB.lru = reqcache.NewLRUCache(10000, DB.getobject, nil)

	return nil
}

var ErrNotFound = errors.New("Not Found")

func (d *db) getobject(ctx context.Context, key interface{}) (interface{}, uint64, error) {
	res, err := d.db.Query("SELECT Value FROM ValueMapping WHERE Hash=?", key.(string))
	if err != nil {
		panic(err)
	}
	defer res.Close()
	var value []byte
	if !res.Next() {
		return nil, 0, ErrNotFound
	}
	err = res.Scan(&value)
	if err != nil {
		panic(err)
	}
	return value, 1, nil
}

func (d *db) InsertObject(hash []byte, object []byte) error {
	k := base64.URLEncoding.EncodeToString(hash)
	d.lru.Put(k, object, 1)
	tx, err := d.db.Begin()
	if err != nil {
		panic(err)
	}
	_, err = tx.Exec("INSERT INTO ValueMapping (Hash, Value) VALUES (?, ?)", k, object)
	if err != nil {
		panic(err)
	}
	err = tx.Commit()
	if err != nil {
		panic(err)
	}
	return nil
}
func (d *db) RetrieveObject(hash []byte) ([]byte, error) {
	k := base64.URLEncoding.EncodeToString(hash)
	obj, err := d.lru.Get(context.Background(), k)
	if err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return obj.([]byte), nil
}

func (d *db) InsertSignedMapRoot(v *dbSMR) error {
	d.mu.Lock()
	d.sigRoots[v.SigIdentity] = v
	d.mu.Unlock()
	return nil
}

type dbSMR struct {
	Revision    uint64
	SigIdentity string
	Timestamp   int64
	R           *big.Int
	S           *big.Int

	//Proof the SMR is in the log
	LogInclusion  []byte
	LogSignedRoot []byte
	LogSize       int64
}

func (d *db) GetLatestMapRootSignature(identities []string) (*dbSMR, error) {
	var found *dbSMR
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, id := range identities {
		e, ok := d.sigRoots[id]
		if ok && (found == nil || found.Revision < e.Revision) {
			found = e
		}
	}
	return found, nil
}
