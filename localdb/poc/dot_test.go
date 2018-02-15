package poc

import (
	"context"
	"testing"

	"github.com/immesys/wave/iapi"
	"github.com/stretchr/testify/require"
)

func mkAtt(t *testing.T, src *iapi.EntitySecrets, dst *iapi.EntitySecrets) (*iapi.EntitySecrets, *iapi.EntitySecrets, *iapi.Attestation) {
	if src == nil {
		rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
		require.NoError(t, err)
		src = rne.EntitySecrets
	}
	if dst == nil {
		rne, err := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
		require.NoError(t, err)
		dst = rne.EntitySecrets
	}
	policy, _ := iapi.NewTrustLevelPolicy(3)
	rv, err := iapi.NewParsedAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy:     policy,
		HashScheme: iapi.KECCAK256,
		BodyScheme: iapi.PLAINTEXTBODYSCHEME,
		Attester:   src,
		Subject:    dst.Entity,
	})
	require.NoError(t, err)
	return src, dst, rv.Attestation
}

func TestAttPending(t *testing.T) {
	ctx := getPctx()
	_, _, att := mkAtt(t, nil, nil)
	cereal, err := att.DER()
	require.NoError(t, err)

	err = db.MoveAttestationPendingP(ctx, att, 0)
	require.NoError(t, err)
	hash := att.Keccak256HI()
	rv, err := db.GetAttestationP(ctx, hash)
	require.NoError(t, err)
	require.NotNil(t, rv)
	rcereal, err := rv.DER()
	require.NoError(t, err)
	require.EqualValues(t, cereal, rcereal)
	//See if it shows up in pending atts
	count := 0
	for pe := range db.GetPendingAttestationsP(ctx, att.Subject(), 3) {
		require.NoError(t, pe.Err)
		readback := pe.Attestation
		require.EqualValues(t, pe.Keccak256, readback.Keccak256())
		require.NotNil(t, pe.LabelKeyIndex)
		require.EqualValues(t, 0, *pe.LabelKeyIndex)
		count++
	}
	require.EqualValues(t, 1, count)
	//Lets set its key index and see that sticks
	err = db.UpdateAttestationPendingP(ctx, att, 3)
	require.NoError(t, err)
	count = 0
	//Check the pending atts really only returns LT on the secret index
	for pe := range db.GetPendingAttestationsP(ctx, att.Subject(), 3) {
		require.NoError(t, pe.Err)
		count++
	}
	require.EqualValues(t, 0, count)

	count = 0
	//Check it shows up with the right secret index
	for pe := range db.GetPendingAttestationsP(ctx, att.Subject(), 4) {
		require.NoError(t, pe.Err)
		readback := pe.Attestation
		require.EqualValues(t, pe.Keccak256, readback.Keccak256())
		require.NotNil(t, pe.LabelKeyIndex)
		require.EqualValues(t, 3, *pe.LabelKeyIndex)
		count++
	}
	require.EqualValues(t, 1, count)

	//Check it stops showing up if we move it to malformed
	err = db.MoveAttestationMalformedP(ctx, att.Keccak256HI())
	require.NoError(t, err)
	count = 0
	//Check it shows up with the right secret index
	for pe := range db.GetPendingAttestationsP(ctx, att.Subject(), 4) {
		require.NoError(t, pe.Err)
		count++
	}
	require.EqualValues(t, 0, count)
}

func TestAttLabelled(t *testing.T) {
	ctx := getPctx()
	_, _, att := mkAtt(t, nil, nil)
	cereal, err := att.DER()
	require.NoError(t, err)
	att.WR1Partition = make([][]byte, 20)
	att.WR1Partition[0] = []byte("foo")
	att.WR1Partition[1] = []byte("bar")
	err = db.MoveAttestationLabelledP(ctx, att)
	require.NoError(t, err)
	//Check attestation is accessible by hash
	rback, err := db.GetAttestationP(ctx, att.Keccak256HI())
	require.NoError(t, err)
	rcereal, err := rback.DER()
	require.EqualValues(t, cereal, rcereal)
	require.EqualValues(t, att.WR1Partition, rback.WR1Partition)

	//Check it shows up in getLabeledded when its supposed to

	//Not here because its too narrow
	tooNarrow := make([][]byte, 20)
	tooNarrow[0] = []byte("foo")
	tooNarrow[1] = []byte("bar")
	tooNarrow[2] = []byte("thenarrowone")
	count := 0
	for rez := range db.GetLabelledAttestationsP(ctx, att.Subject(), tooNarrow) {
		require.NoError(t, rez.Err)
		count++
	}
	require.EqualValues(t, 0, count)

	//Here because its equal
	count = 0
	for rez := range db.GetLabelledAttestationsP(ctx, att.Subject(), att.WR1Partition) {
		require.NoError(t, rez.Err)
		require.EqualValues(t, rez.Keccak256, att.Keccak256())
		require.EqualValues(t, rez.Attestation.Keccak256(), att.Keccak256())
		count++
	}
	require.EqualValues(t, 1, count)

	//Here because its broader
	broader := make([][]byte, 20)
	broader[0] = []byte("foo")
	count = 0
	for rez := range db.GetLabelledAttestationsP(ctx, att.Subject(), broader) {
		require.NoError(t, rez.Err)
		require.EqualValues(t, rez.Keccak256, att.Keccak256())
		require.EqualValues(t, rez.Attestation.Keccak256(), att.Keccak256())
		count++
	}
	require.EqualValues(t, 1, count)
}

func TestAttActive(t *testing.T) {
	ctx := getPctx()
	src, _, att := mkAtt(t, nil, nil)
	count := 0
	for rez := range db.GetActiveAttestationsFromP(ctx, src.Entity.Keccak256HI(), &iapi.LookupFromFilter{}) {
		require.NoError(t, rez.Err)
		count++
	}
	require.EqualValues(t, 0, count)
	err := db.MoveAttestationActiveP(ctx, att)
	require.NoError(t, err)
	count = 0
	for rez := range db.GetActiveAttestationsFromP(ctx, src.Entity.Keccak256HI(), &iapi.LookupFromFilter{}) {
		require.NoError(t, rez.Err)
		count++
	}
	require.EqualValues(t, 1, count)
	count = 0
	err = db.MoveAttestationRevokedG(ctx, att)
	for rez := range db.GetActiveAttestationsFromP(ctx, src.Entity.Keccak256HI(), &iapi.LookupFromFilter{}) {
		require.NoError(t, rez.Err)
		count++
	}
	require.EqualValues(t, 1, count)
	count = 0
	for rez := range db.GetActiveAttestationsFromP(ctx, src.Entity.Keccak256HI(), &iapi.LookupFromFilter{Valid: iapi.Bool(true)}) {
		require.NoError(t, rez.Err)
		count++
	}
	require.EqualValues(t, 0, count)
}

//
// //This is a key that decrypts the partition label (WR1 uses IBE)
// GetPartitionLabelKeyP(ctx context.Context, subject HashSchemeInstance, index int) (EntitySecretKeySchemeInstance, error)
// InsertPartitionLabelKeyP(ctx context.Context, attester HashSchemeInstance, key EntitySecretKeySchemeInstance) (new bool, err error)
// WR1KeysForP(ctx context.Context, subject HashSchemeInstance, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
// InsertWR1KeysForP(ctx context.Context, attester HashSchemeInstance, k SlottedSecretKey) error
// GetEntityPartitionLabelKeyIndexP(ctx context.Context, entHashSchemeInstance HashSchemeInstance) (bool, int, error)

// GetEntityQueueIndexP(ctx context.Context, hsh HashSchemeInstance) (okay bool, dotIndex int, err error)
// SetEntityQueueIndexP(ctx context.Context, hsh HashSchemeInstance, dotIndex int) error
// GetEntityByHashSchemeInstanceG(ctx context.Context, hsh HashSchemeInstance) (*Entity, error)
