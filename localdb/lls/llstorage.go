package lls

import (
	"context"

	localdb "github.com/immesys/wave/localdb/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type lls struct {
	db *leveldb.DB
}

//Check it implements interface
var _ localdb.LowLevelStorage = &lls{}

func NewLowLevelStorage(dbpath string) (localdb.LowLevelStorage, error) {
	db, err := leveldb.OpenFile("path/to/db", nil)
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
func (s *lls) LoadPrefix(ctx context.Context, key string) (chan localdb.KeyValue, chan error) {
	rvv := make(chan localdb.KeyValue, 10)
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
func (s *lls) LoadPrefixKeys(ctx context.Context, key string) (chan localdb.KeyValue, chan error) {
	//Deliberately remove values to prevent code from accidentally using them
	rvv := make(chan localdb.KeyValue, 10)
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
func (s *lls) loadPrefix(ctx context.Context, key string, includeValue bool, rvv chan localdb.KeyValue, rve chan error) {
	iter := s.db.NewIterator(util.BytesPrefix([]byte(key)), nil)
	for iter.Next() {
		e := localdb.KeyValue{
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
