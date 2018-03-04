package poc

import (
	"bytes"
	"context"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/stretchr/testify/require"
)

var db iapi.WaveState

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
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if err != nil {
		panic(err)
	}
	perspective := rne.EntitySecrets
	ctx := context.WithValue(context.Background(), consts.PerspectiveKey, perspective)
	return ctx
}
func TestStoreLoadEntity(t *testing.T) {
	ctx := getPctx()
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if err != nil {
		panic(err)
	}
	perspective := rne.EntitySecrets
	ent := perspective.Entity
	firstSer, err := ent.DER()
	require.NoError(t, err)
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err = db.MoveEntityInterestingP(ctx, ent, tloc)
	require.NoError(t, err)
	hi, err := ent.Hash(context.Background(), iapi.KECCAK256)
	require.NoError(t, err)

	rent, err := db.GetEntityByHashSchemeInstanceG(ctx, hi)
	require.NoError(t, err)
	secondSer, err := rent.DER()
	require.NoError(t, err)
	if !bytes.Equal(firstSer, secondSer) {
		t.Fatalf("entities not equal when serialized")
	}
}

func TestEntityQueueToken(t *testing.T) {
	ctx := getPctx()
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if err != nil {
		panic(err)
	}
	perspective := rne.EntitySecrets
	ent := perspective.Entity
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err = db.MoveEntityInterestingP(ctx, ent, tloc)
	if err != nil {
		t.Fatal(err)
	}
	okay, doti, err := db.GetEntityQueueTokenP(ctx, tloc, ent.Keccak256HI())
	require.NoError(t, err)
	require.True(t, okay)
	require.EqualValues(t, "", doti)
	err = db.SetEntityQueueTokenP(ctx, tloc, ent.Keccak256HI(), "5")
	if err != nil {
		t.Fatal(err)
	}
	okay, doti, err = db.GetEntityQueueTokenP(ctx, tloc, ent.Keccak256HI())
	if err != nil {
		t.Fatal(err)
	}
	if !okay {
		t.Fatal(okay)
	}
	if doti != "5" {
		t.Fatal(doti)
	}
}

func TestNonExistingEntityByHash(t *testing.T) {
	ctx := getPctx()
	hash := make([]byte, 32)
	rand.Read(hash)
	ent, err := db.GetEntityByHashSchemeInstanceG(ctx, &iapi.HashSchemeInstance_Keccak_256{hash})
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
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	okay, _, err := db.GetEntityQueueTokenP(ctx, tloc, &iapi.HashSchemeInstance_Keccak_256{hash})
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
	intr, err := db.IsEntityInterestingP(ctx, &iapi.HashSchemeInstance_Keccak_256{hash})
	if err != nil {
		t.Fatal(err)
	}
	if intr {
		t.Fatalf("not false?")
	}
}

func TestInterestingEntity(t *testing.T) {
	ctx := getPctx()
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if err != nil {
		panic(err)
	}
	ent := rne.EntitySecrets.Entity
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err = db.MoveEntityInterestingP(ctx, ent, tloc)
	if err != nil {
		t.Fatal(err)
	}
	intr, err := db.IsEntityInterestingP(ctx, ent.Keccak256HI())
	if err != nil {
		t.Fatal(err)
	}
	if !intr {
		t.Fatalf("not true?")
	}
}

func TestInterestingEntityRevoked(t *testing.T) {
	ctx := getPctx()
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, err)
	ent := rne.EntitySecrets.Entity
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err = db.MoveEntityInterestingP(ctx, ent, tloc)
	require.NoError(t, err)
	intr, err := db.IsEntityInterestingP(ctx, ent.Keccak256HI())
	require.NoError(t, err)
	require.True(t, intr)
	err = db.MoveEntityRevokedG(ctx, ent)
	intr, err = db.IsEntityInterestingP(ctx, ent.Keccak256HI())
	require.NoError(t, err)
	require.False(t, intr)
}

func TestInterestingEntityExpired(t *testing.T) {
	ctx := getPctx()
	rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, err)
	ent := rne.EntitySecrets.Entity
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err = db.MoveEntityInterestingP(ctx, ent, tloc)
	require.NoError(t, err)
	intr, err := db.IsEntityInterestingP(ctx, ent.Keccak256HI())
	require.NoError(t, err)
	require.True(t, intr)
	err = db.MoveEntityExpiredG(ctx, ent)
	intr, err = db.IsEntityInterestingP(ctx, ent.Keccak256HI())
	require.NoError(t, err)
	require.False(t, intr)
}

func TestInterestingEntitySequence(t *testing.T) {
	ctx := getPctx()
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	dataset := make(map[[32]byte]*iapi.Entity)
	for i := 0; i < 100; i++ {
		rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
		require.NoError(t, err)
		ent := rne.EntitySecrets.Entity
		dataset[ent.ArrayKeccak256()] = ent
		err = db.MoveEntityInterestingP(ctx, ent, tloc)
		require.NoError(t, err)
	}
	rvc := db.GetInterestingEntitiesP(ctx)
	for v := range rvc {
		require.NoError(t, v.Err)
		_, ok := dataset[v.Entity.ArrayKeccak256()]
		require.True(t, ok)
		delete(dataset, v.Entity.ArrayKeccak256())
	}
	if len(dataset) != 0 {
		t.Fatalf("we did not get back all entities, there are %d left", len(dataset))
	}
}

func TestInterestingEntitySequenceRevokedExpired(t *testing.T) {
	ctx := getPctx()
	entz := make([]*iapi.Entity, 0)
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	for i := 0; i < 100; i++ {
		rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
		require.NoError(t, err)
		ent := rne.EntitySecrets.Entity
		err = db.MoveEntityInterestingP(ctx, ent, tloc)
		require.NoError(t, err)
		entz = append(entz, ent)
	}
	err := db.MoveEntityExpiredG(ctx, entz[0])
	require.NoError(t, err)
	err = db.MoveEntityRevokedG(ctx, entz[1])
	require.NoError(t, err)
	count := 0
	rvc := db.GetInterestingEntitiesP(ctx)
	for v := range rvc {
		require.NoError(t, v.Err)
		count++
	}
	require.EqualValues(t, 98, count)
}

//
// func TestEntityByRevocation(t *testing.T) {
// 	ctx := getPctx()
// 	ent := entity.NewEntity(params.LocationUC)
// 	firstSer, err := ent.SerializePrivate()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	err = db.MoveEntityInterestingP(ctx, ent)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	rvc := db.GetInterestingByRevocationHashP(ctx, ent.RevocationHash)
// 	count := 0
// 	for v := range rvc {
// 		count++
// 		if v.Err != nil {
// 			t.Fatal(v.Err)
// 		}
// 		if v.IsDOT {
// 			t.Fatalf("expected false")
// 		}
// 		if v.Entity == nil {
// 			t.Fatalf("expected entty")
// 		}
// 		secondSer, err := v.Entity.SerializePrivate()
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if !bytes.Equal(firstSer, secondSer) {
// 			t.Fatalf("entities not equal when serialized")
// 		}
// 	}
// 	if count != 1 {
// 		t.Fatalf("expected count to be 1")
// 	}
// }

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
