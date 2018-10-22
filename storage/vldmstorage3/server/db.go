package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/go-sql-driver/mysql"
	"github.com/samkumar/reqcache"
)

type db struct {
	db   *sql.DB
	mu   sync.RWMutex
	root *dbSMR
	lru  *reqcache.LRUCache
}

var DB *db

func InitDB(connstring string) error {
	h, err := sql.Open("mysql", connstring)
	if err != nil {
		return err
	}
	DB = &db{
		db: h,
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

var ErrAlreadyExists = errors.New("Already exists\n")

func (d *db) InsertObject(hash []byte, object []byte) error {
	k := base64.URLEncoding.EncodeToString(hash)
	d.lru.Put(k, object, 1)
	tx, err := d.db.Begin()
	if err != nil {
		panic(err)
	}
	_, err = tx.Exec("INSERT INTO ValueMapping (Hash, Value) VALUES (?, ?)", k, object)
	if err != nil {
		me, ok := err.(*mysql.MySQLError)
		if !ok {
			panic(err)
		}
		if me.Number == 1062 {
			//Record already existed
			tx.Rollback()
			return ErrAlreadyExists
		} else {
			panic(err)
		}
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

func (d *db) InsertMapRoot(v *dbSMR) error {
	d.mu.Lock()
	d.root = v
	d.mu.Unlock()
	return nil
}

type dbSMR struct {
	Revision uint64

	//Proof the SMR is in the log
	LogInclusion  []byte
	LogSignedRoot []byte
	LogSize       int64
}

func (d *db) GetLatestMapRoot() *dbSMR {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.root
}
