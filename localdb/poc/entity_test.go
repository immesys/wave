package poc

import (
	"bytes"
	"context"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/types"
)

var db types.WaveState

func init() {
	tdir, _ := ioutil.TempDir("", "llstest")
	llsdb, err := lls.NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
	//Put in your WS implementation here
	db = NewPOC(llsdb)
}
func getPctx() context.Context {
	perspective := entity.NewEntity()
	ctx := context.WithValue(context.Background(), engine.PerspectiveKey, perspective)
	return ctx
}
func TestStoreLoadEntity(t *testing.T) {
	ctx := getPctx()
	ent := entity.NewEntity()
	firstSer, err := ent.SerializePrivate()
	if err != nil {
		t.Fatal(err)
	}
	err = db.MoveEntityInterestingP(ctx, ent)
	if err != nil {
		t.Fatal(err)
	}
	rent, err := db.GetEntityByHashG(ctx, ent.Hash)
	if err != nil {
		t.Fatal(err)
	}
	secondSer, err := rent.SerializePrivate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstSer, secondSer) {
		t.Fatalf("entities not equal when serialized")
	}
}

func TestEntityDotIndex(t *testing.T) {
	ctx := getPctx()
	ent := entity.NewEntity()
	err := db.MoveEntityInterestingP(ctx, ent)
	if err != nil {
		t.Fatal(err)
	}
	okay, doti, err := db.GetEntityDotIndexP(ctx, ent.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !okay {
		t.Fatal(okay)
	}
	if doti != 0 {
		t.Fatal(doti)
	}
	err = db.SetEntityDotIndexP(ctx, ent.Hash, 5)
	if err != nil {
		t.Fatal(err)
	}
	okay, doti, err = db.GetEntityDotIndexP(ctx, ent.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !okay {
		t.Fatal(okay)
	}
	if doti != 5 {
		t.Fatal(doti)
	}
}

func TestNonExistingEntityByHash(t *testing.T) {
	ctx := getPctx()
	hash := make([]byte, 32)
	rand.Read(hash)
	ent, err := db.GetEntityByHashG(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if ent != nil {
		t.Fatalf("not nil?")
	}
}

func TestNonExistingEntityDotIndex(t *testing.T) {
	ctx := getPctx()
	hash := make([]byte, 32)
	rand.Read(hash)
	okay, _, err := db.GetEntityDotIndexP(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if okay {
		t.Fatalf("expected okay=false")
	}
}

func TestNonExistingEntityInteresting(t *testing.T) {
	ctx := getPctx()
	hash := make([]byte, 32)
	rand.Read(hash)
	intr, err := db.IsEntityInterestingP(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if intr {
		t.Fatalf("not false?")
	}
}

func TestInterestingEntity(t *testing.T) {
	ctx := getPctx()
	ent := entity.NewEntity()
	err := db.MoveEntityInterestingP(ctx, ent)
	if err != nil {
		t.Fatal(err)
	}
	intr, err := db.IsEntityInterestingP(ctx, ent.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !intr {
		t.Fatalf("not true?")
	}
}

func TestInterestingEntitySequence(t *testing.T) {
	ctx := getPctx()
	dataset := make(map[[32]byte]*entity.Entity)
	for i := 0; i < 100; i++ {
		ent := entity.NewEntity()
		dataset[ent.ArrayHash()] = ent
		err := db.MoveEntityInterestingP(ctx, ent)
		if err != nil {
			t.Fatal(err)
		}
	}
	rvc := db.GetInterestingEntitiesP(ctx)
	for v := range rvc {
		if v.Err != nil {
			t.Fatal(v.Err)
		}
		_, ok := dataset[entity.ArrayHash(v.Hash)]
		if !ok {
			t.Fatalf("bad hash")
		}
		delete(dataset, entity.ArrayHash(v.Hash))
	}
	if len(dataset) != 0 {
		t.Fatalf("we did not get back all entities, there are %d left", len(dataset))
	}
}
func TestEntityByRevocation(t *testing.T) {
	ctx := getPctx()
	ent := entity.NewEntity()
	firstSer, err := ent.SerializePrivate()
	if err != nil {
		t.Fatal(err)
	}
	err = db.MoveEntityInterestingP(ctx, ent)
	if err != nil {
		t.Fatal(err)
	}
	rvc := db.GetInterestingByRevocationHashP(ctx, ent.RevocationHash)
	count := 0
	for v := range rvc {
		count++
		if v.Err != nil {
			t.Fatal(v.Err)
		}
		if v.IsDOT {
			t.Fatalf("expected false")
		}
		if v.Entity == nil {
			t.Fatalf("expected entty")
		}
		secondSer, err := v.Entity.SerializePrivate()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(firstSer, secondSer) {
			t.Fatalf("entities not equal when serialized")
		}
	}
	if count != 1 {
		t.Fatalf("expected count to be 1")
	}
}

// for dots
// GetInterestingByRevocationHashP(ctx context.Context, rvkhash []byte) chan ReverseLookupResult
//
// GetPartitionLabelKeyP(ctx context.Context, dst []byte, index int) (*Secret, error)
// InsertPartitionLabelKeyP(ctx context.Context, from []byte, namespace []byte, key *oaque.PrivateKey) (new bool, err error)
//
// OAQUEKeysForP(ctx context.Context, dst []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error
// //TODO this must be idempotenty, like don't add in a secret if we have a more
// //powerful one already
// InsertOAQUEKeysForP(ctx context.Context, from []byte, slots [][]byte, k *oaque.PrivateKey) error
//
// MoveDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error
// //Assume dot already inserted into pending, but update the labelKeyIndex
// UpdateDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error
// MoveDotLabelledP(ctx context.Context, dt *dot.DOT) error
// MoveDotActiveP(ctx context.Context, dt *dot.DOT) error
// MoveDotExpiredP(ctx context.Context, dt *dot.DOT) error
// MoveDotEntRevokedP(ctx context.Context, dt *dot.DOT) error
// MoveDotMalformedP(ctx context.Context, hash []byte) error
// GetLabelledDotsP(ctx context.Context, dst []byte, partition [][]byte) chan PendingDOTResult
// //If possible, only return pending dots with a secret index less than siLT
// GetPendingDotsP(ctx context.Context, dst []byte, lkiLT int) chan PendingDOTResult
// GetEntityPartitionLabelKeyIndexP(ctx context.Context, enthash []byte) (bool, int, error)
// GetDotP(ctx context.Context, hash []byte) (d *dot.DOT, err error)
// GetActiveDotsFromP(ctx context.Context, src []byte, filter *LookupFromFilter) chan LookupFromResult

//
// //Global (non perspective) functions
// MoveEntityRevokedG(ctx context.Context, ent *entity.Entity) error
// MoveEntityExpiredG(ctx context.Context, ent *entity.Entity) error
// MoveDotRevokedG(ctx context.Context, dot *dot.DOT) error
//
// //This only returns entities we happen to have because they were interesting
// //to someone, so the caller must handle a nil,nil result and go hit the chain
// GetEntityByHashG(ctx context.Context, hsh []byte) (*entity.Entity, error)
