package lls

import (
	"bytes"
	"context"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/immesys/wave/iapi"
)

var db iapi.LowLevelStorage

func init() {
	tdir, _ := ioutil.TempDir("", "llstest")
	var err error
	db, err = NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
}

func TestStoreLoad(t *testing.T) {
	//Test with binary keys to ensure DB can handle that mayhem
	keyb := make([]byte, 32)
	rand.Read(keyb)
	key := string(keyb)
	val := make([]byte, 32)
	rand.Read(val)
	err := db.Store(context.Background(), key, val)
	if err != nil {
		t.Fatalf("unexpected store error: %v", err)
	}

	//Now load it
	rval, err := db.Load(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if rval == nil {
		t.Fatalf("unexpected nil value")
	}
	if !bytes.Equal(rval, val) {
		t.Fatalf("unexpected value mismatch on read")
	}
}

func TestLoadNonExistant(t *testing.T) {
	keyb := make([]byte, 32)
	rand.Read(keyb)
	key := string(keyb)
	val, err := db.Load(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if val != nil {
		t.Fatalf("expected a nil value")
	}
}

func TestLoadNonExistantRange(t *testing.T) {
	keyb := make([]byte, 32)
	rand.Read(keyb)
	key := string(keyb)
	rvv, rve := db.LoadPrefixKeys(context.Background(), key)
	_, ok := <-rvv
	if ok {
		t.Fatalf("expected no results on value channel")
	}
	err, ok := <-rve
	if !ok {
		t.Fatalf("expected something on the error channel")
	}
	if err != nil {
		t.Fatalf("expected nil error")
	}
}
func TestStoreLoadRange(t *testing.T) {
	//Test with binary keys to ensure DB can handle that mayhem
	keyb := make([]byte, 32)
	rand.Read(keyb)
	dataset := []iapi.KeyValue{}
	for i := 0; i < 10; i++ {
		keyarr := make([]byte, 64)
		copy(keyarr, keyb)
		rand.Read(keyarr[32:])
		keyarr[32] = byte(i) //ordering
		val := make([]byte, 32)
		rand.Read(val)
		key := string(keyarr)
		dataset = append(dataset, iapi.KeyValue{Key: key, Value: val})
		err := db.Store(context.Background(), key, val)
		if err != nil {
			t.Fatalf("unexpected store error: %v", err)
		}
	}
	//spew.Dump(dataset)
	//Also insert some random other stuff
	for i := 0; i < 10; i++ {
		rkeyb := make([]byte, 32)
		rand.Read(rkeyb)
		rkey := string(rkeyb)
		err := db.Store(context.Background(), rkey, rkeyb)
		if err != nil {
			t.Fatalf("unexpected store error: %v", err)
		}
	}
	//Now query range and ensure its only what we want
	valchan, errchan := db.LoadPrefix(context.Background(), string(keyb))
	for _, expected := range dataset {
		got, ok := <-valchan
		if !ok {
			t.Fatalf("expected another value")
		}
		if got.Key != expected.Key {
			t.Fatalf("wrong key")
		}
		if !bytes.Equal(got.Value, expected.Value) {
			t.Fatalf("wrong value got (%d)%x, expected (%d)%x", len(got.Value), got.Value, len(expected.Value), expected.Value)
		}
	}
	_, ok := <-valchan
	if ok {
		t.Fatalf("expected value channel to be closed")
	}
	err, ok := <-errchan
	if !ok {
		t.Fatalf("expected something on the error channel")
	}
	if err != nil {
		t.Fatalf("expected nil error")
	}
	//Now query range keys and ensure its only what we want
	valchan, errchan = db.LoadPrefixKeys(context.Background(), string(keyb))
	for _, expected := range dataset {
		got, ok := <-valchan
		if !ok {
			t.Fatalf("expected another value")
		}
		if got.Key != expected.Key {
			t.Fatalf("wrong key")
		}
		if got.Value != nil {
			t.Fatalf("expected nil value")
		}
	}
	_, ok = <-valchan
	if ok {
		t.Fatalf("expected value channel to be closed")
	}
	err, ok = <-errchan
	if !ok {
		t.Fatalf("expected something on the error channel")
	}
	if err != nil {
		t.Fatalf("expected nil error")
	}
}

func TestStoreLoadRangeCancel(t *testing.T) {
	keyb := make([]byte, 32)
	rand.Read(keyb)
	dataset := []iapi.KeyValue{}
	for i := 0; i < 100; i++ {
		keyarr := make([]byte, 64)
		copy(keyarr, keyb)
		rand.Read(keyarr[32:])
		keyarr[32] = byte(i) //ordering
		val := make([]byte, 32)
		rand.Read(val)
		key := string(keyarr)
		dataset = append(dataset, iapi.KeyValue{Key: key, Value: val})
		err := db.Store(context.Background(), key, val)
		if err != nil {
			t.Fatalf("unexpected store error: %v", err)
		}
	}
	//Now query range and cancel context half way
	ctx, cancel := context.WithCancel(context.Background())
	valchan, errchan := db.LoadPrefix(ctx, string(keyb))
	for i := 0; i < 30; i++ {
		_, ok := <-valchan
		if !ok {
			t.Fatalf("expected values")
		}
	}
	cancel()
	err, ok := <-errchan
	if !ok {
		t.Fatalf("expected something on the error channel")
	}
	if err != context.Canceled {
		t.Fatalf("expected cancelled error")
	}
}

// Load(ctx context.Context, key string) (val []byte, err error)
// LoadPrefix(ctx context.Context, key string) (results chan KeyValue, err chan error)
// //Values will be nil
// LoadPrefixKeys(ctx context.Context, key string) (results chan KeyValue, err chan error)
// Store(ctx context.Context, key string, val []byte) (err error)
