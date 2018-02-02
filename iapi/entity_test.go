package iapi

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestCreateEntity(t *testing.T) {
	R, err := NewEntity(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	//fmt.Printf("Public part: %x\n", R.PublicDER)
	//fmt.Printf("Secret part: %x\n", R.SecretDER)
	readback, err := ParseEntity(context.Background(), &PParseEntity{
		DER: R.PublicDER,
	})
	require.NoError(t, err)
	spew.Dump(readback.Entity)
}
