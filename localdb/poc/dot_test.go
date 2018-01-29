package poc

import (
	"bytes"
	"testing"

	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/params"
)

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

func TestMoveDotPendingP(t *testing.T) {
	ctx := getPctx()
	srcent := entity.NewEntity(params.LocationUC)
	dstent := entity.NewEntity(params.LocationUC)

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
