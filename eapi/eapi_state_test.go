package eapi

import (
	"context"
	"testing"

	"github.com/immesys/wave/eapi/pb"
	"github.com/stretchr/testify/require"
)

func TestEntityRevocation(t *testing.T) {
	ctx := context.Background()
	_, secret, hash := createAndPublishEntity(t)

	persp := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: secret,
		},
		Location: &inmem,
	}

	l1, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        hash,
		Perspective: persp,
	})
	require.NoError(t, err)
	require.NotNil(t, l1.Entity)
	require.True(t, l1.Entity.Validity.Valid)

	rvkr, err := eapi.Revoke(ctx, &pb.RevokeParams{
		Perspective:       persp,
		RevokePerspective: true,
	})
	require.NoError(t, err)
	require.Nil(t, rvkr.Error)

	l2, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        hash,
		Perspective: persp,
	})
	require.NoError(t, err)
	require.NotNil(t, l2.Entity)
	require.False(t, l2.Entity.Validity.Valid)
	require.True(t, l2.Entity.Validity.Revoked)

}
