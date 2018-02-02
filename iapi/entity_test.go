package iapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateEntity(t *testing.T) {
	R, err := IAPI.NewEntity(context.Background(), &PNewEntity{})
	require.NoError(t, err)
	fmt.Printf("Public part: %x\n", R.PublicDER)
	fmt.Printf("Secret part: %x\n", R.SecretDER)
}
