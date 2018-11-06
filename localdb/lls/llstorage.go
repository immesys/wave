package lls

import (
	"context"
	"fmt"

	"github.com/immesys/wave/iapi"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type lls struct {
	db *leveldb.DB
}

//Check it implements interface
var _ iapi.LowLevelStorage = &lls{}

func NewLowLevelStorage(dbpath string) (iapi.LowLevelStorage, error) {
	fmt.Printf("lls at %q\n", dbpath)
	db, err := leveldb.OpenFile(dbpath, nil)
	if err != nil {
		return nil, err
	}
	rv := lls{
		db: db,
	}
	return &rv, nil
}
func (s *lls) Load(ctx context.Context, key string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	val, err := s.db.Get([]byte(key), nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}
func (s *lls) LoadPrefix(ctx context.Context, key string) (chan iapi.KeyValue, chan error) {
	rvv := make(chan iapi.KeyValue, 10)
	rve := make(chan error, 1)
	if ctx.Err() != nil {
		rve <- ctx.Err()
		close(rvv)
		close(rve)
		return rvv, rve
	}
	go s.loadPrefix(ctx, key, true, rvv, rve)
	return rvv, rve
}

//For some databases, e.g badger, this might be more efficient. For us its the same
func (s *lls) LoadPrefixKeys(ctx context.Context, key string) (chan iapi.KeyValue, chan error) {
	//Deliberately remove values to prevent code from accidentally using them
	rvv := make(chan iapi.KeyValue, 10)
	rve := make(chan error, 1)
	if ctx.Err() != nil {
		rve <- ctx.Err()
		close(rvv)
		close(rve)
		return rvv, rve
	}
	go s.loadPrefix(ctx, key, false, rvv, rve)
	return rvv, rve
}
func (s *lls) loadPrefix(ctx context.Context, key string, includeValue bool, rvv chan iapi.KeyValue, rve chan error) {
	iter := s.db.NewIterator(util.BytesPrefix([]byte(key)), nil)
	for iter.Next() {
		e := iapi.KeyValue{
			Key: string(iter.Key()),
		}
		if includeValue {
			val := make([]byte, len(iter.Value()))
			copy(val, iter.Value())
			e.Value = val
		}
		select {
		case rvv <- e:
		case <-ctx.Done():
			iter.Release()
			rve <- ctx.Err()
			close(rvv)
			close(rve)
			return
		}
	}
	rve <- iter.Error()
	close(rvv)
	close(rve)
	iter.Release()
}

func (s *lls) Store(ctx context.Context, key string, val []byte) error {
	return s.db.Put([]byte(key), val, nil)
}

func (s *lls) Remove(ctx context.Context, key string) error {
	return s.db.Delete([]byte(key), nil)
}
