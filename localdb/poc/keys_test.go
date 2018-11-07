package poc

import (
	"context"
	"testing"

	"github.com/immesys/wave/iapi"
	"github.com/stretchr/testify/require"
)

func TestKeyPartitionLabel(t *testing.T) {
	ctx := getPctx()
	rne, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if werr != nil {
		panic(werr)
	}
	es := rne.EntitySecrets
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err := db.MoveEntityInterestingP(ctx, es.Entity, tloc)
	require.NoError(t, err)

	ok, index, err := db.GetEntityPartitionLabelKeyIndexP(ctx, es.Entity.Keccak256HI())
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 0, index)

	k, err := es.WR1LabelKey(ctx, []byte("foo"))
	require.NoError(t, err)
	pub := k.Public()

	ciphertext, err := pub.EncryptMessage(ctx, []byte("helloworld"))
	require.NoError(t, err)
	new, err := db.InsertPartitionLabelKeyP(ctx, es.Entity.Keccak256HI(), k)
	require.True(t, new)
	require.NoError(t, err)

	new, err = db.InsertPartitionLabelKeyP(ctx, es.Entity.Keccak256HI(), k)
	require.False(t, new)
	require.NoError(t, err)

	ok, index, err = db.GetEntityPartitionLabelKeyIndexP(ctx, es.Entity.Keccak256HI())
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, index)

	sk, err := db.GetPartitionLabelKeyP(ctx, es.Entity.Keccak256HI(), 0)
	require.NoError(t, err)
	require.NotNil(t, sk)
	plaintext, err := sk.DecryptMessage(ctx, ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, []byte("helloworld"), plaintext)
}

func TestWR1Keys(t *testing.T) {
	ctx := getPctx()
	rne, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	if werr != nil {
		panic(werr)
	}
	es := rne.EntitySecrets
	tloc := iapi.NewLocationSchemeInstanceURL("test", 1)
	err := db.MoveEntityInterestingP(ctx, es.Entity, tloc)
	require.NoError(t, err)
	slots := make([][]byte, 20)
	slots[0] = []byte("foo")
	slots[1] = []byte("bar")
	wr1body, err := es.WR1BodyKey(ctx, slots, true)
	require.NoError(t, err)
	err = db.InsertWR1KeysForP(ctx, es.Entity.Keccak256HI(), wr1body)
	require.NoError(t, err)

	//First try narrow (it should work)
	tooNarrow := make([][]byte, 20)
	tooNarrow[0] = []byte("foo")
	tooNarrow[1] = []byte("bar")
	tooNarrow[2] = []byte("thenarrowone")
	count := 0
	err = db.WR1KeysForP(ctx, es.Entity.Keccak256HI(), tooNarrow, func(k iapi.SlottedSecretKey) bool {
		count++
		return true
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)

	//Then try equal
	equal := make([][]byte, 20)
	equal[0] = []byte("foo")
	equal[1] = []byte("bar")
	count = 0
	err = db.WR1KeysForP(ctx, es.Entity.Keccak256HI(), equal, func(k iapi.SlottedSecretKey) bool {
		count++
		return true
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)

	//Then try too broad (should not work)
	broad := make([][]byte, 20)
	broad[0] = []byte("foo")
	count = 0
	err = db.WR1KeysForP(ctx, es.Entity.Keccak256HI(), broad, func(k iapi.SlottedSecretKey) bool {
		count++
		return true
	})
	require.NoError(t, err)
	require.EqualValues(t, 0, count)
}
