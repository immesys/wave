package iapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWR1Partition(t *testing.T) {
	rv, err := CalculateKeyBundlePartitions(time.Now(), time.Now().Add(700*24*time.Hour), [][]byte{[]byte("foo"), []byte("bar")})
	require.NoError(t, err)

	for idx, e := range rv {
		desc := WR1PartitionToString(e)
		fmt.Printf("%3d :  %s\n", idx, desc)
	}
	for idx, e := range rv {
		desc := WR1PartitionToString(e)
		sr, er, _, err := ParseWR1Partition(e)
		require.NoError(t, err)
		if sr.End.Add(3 * 365 * 24 * time.Hour).Before(er.Start) {
			fmt.Printf("could prune: %3d : %s\n", idx, desc)
		}
	}
}

func TestWR1PartitionCompress(t *testing.T) {
	rvp, rvb, err := CalculateEmptyKeyBundleEntries(time.Now(), time.Now().Add(700*24*time.Hour), [][]byte{[]byte("foo"), []byte("bar")})
	require.NoError(t, err)
	require.NotNil(t, rvp)

	parts, err := DecodeKeyBundleEntries(rvb)
	require.NoError(t, err)
	require.EqualValues(t, parts, rvp)
}
