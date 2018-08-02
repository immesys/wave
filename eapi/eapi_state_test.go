package eapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
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

func TestAttestationRevocationUndecrypted(t *testing.T) {
	ctx := context.Background()
	_, scA, _ := createAndPublishEntity(t)
	_, scB, _ := createAndPublishEntity(t)
	_, _, hC := createAndPublishEntity(t)
	perspA := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scA,
		},
		Location: &inmem,
	}
	perspB := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scB,
		},
		Location: &inmem,
	}

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective:     perspA,
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     hC,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)

	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(t, err)
	require.Nil(t, pubresp.Error)

	l1, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        pubresp.Hash,
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.NotNil(t, l1.Attestation)
	require.False(t, l1.Attestation.Validity.Revoked)
	//
	rvkr, err := eapi.Revoke(ctx, &pb.RevokeParams{
		Perspective:     perspA,
		AttestationHash: pubresp.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, rvkr.Error)

	l2, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        pubresp.Hash,
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.NotNil(t, l2.Attestation)
	require.True(t, l2.Attestation.Validity.Revoked)
}

func TestAttestationRevocationDecrypted(t *testing.T) {
	ctx := context.Background()
	_, scA, _ := createAndPublishEntity(t)
	_, scB, hB := createAndPublishEntity(t)
	perspA := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scA,
		},
		Location: &inmem,
	}
	perspB := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scB,
		},
		Location: &inmem,
	}

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective:     perspA,
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     hB,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)

	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(t, err)
	require.Nil(t, pubresp.Error)

	//Resync B's graph:
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: perspB,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete\n")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	l1, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        pubresp.Hash,
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.NotNil(t, l1.Attestation)
	require.False(t, l1.Attestation.Validity.Revoked)
	require.True(t, l1.Attestation.Validity.Valid)

	//
	rvkr, err := eapi.Revoke(ctx, &pb.RevokeParams{
		Perspective:     perspA,
		AttestationHash: pubresp.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, rvkr.Error)

	l2, err := eapi.ResolveHash(ctx, &pb.ResolveHashParams{
		Hash:        pubresp.Hash,
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.NotNil(t, l2.Attestation)
	require.True(t, l2.Attestation.Validity.Revoked)
	require.False(t, l2.Attestation.Validity.Valid)
}

func TestNameDeclarationRevocationPlaintext(t *testing.T) {
	ctx := context.Background()
	_, scA, hA := createAndPublishEntity(t)
	_, scB, hB := createAndPublishEntity(t)
	perspA := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scA,
		},
		Location: &inmem,
	}
	perspB := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: scB,
		},
		Location: &inmem,
	}

	ndr, err := eapi.CreateNameDeclaration(ctx, &pb.CreateNameDeclarationParams{
		Perspective: perspA,
		Name:        "foo",
		Subject:     hB,
	})
	require.NoError(t, err)
	require.Nil(t, ndr.Error)

	ndr2, err := eapi.CreateNameDeclaration(ctx, &pb.CreateNameDeclarationParams{
		Perspective: perspB,
		Name:        "a",
		Subject:     hA,
	})
	require.NoError(t, err)
	require.Nil(t, ndr2.Error)

	//Resync B's graph:
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: perspB,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: perspB,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete\n")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	l1, err := eapi.ResolveName(ctx, &pb.ResolveNameParams{
		Perspective: perspB,
		Name:        "foo.a",
	})
	require.NoError(t, err)
	require.Nil(t, l1.Error)
	require.EqualValues(t, l1.Entity.Hash, hB)
	require.True(t, l1.Derivation[0].Validity.Valid)

	rvkr, err := eapi.Revoke(ctx, &pb.RevokeParams{
		Perspective:         perspA,
		NameDeclarationHash: ndr.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, rvkr.Error)

	l1, err = eapi.ResolveName(ctx, &pb.ResolveNameParams{
		Perspective: perspB,
		Name:        "foo.a",
	})
	spew.Dump(l1.Derivation)
	require.NoError(t, err)
	require.Nil(t, l1.Entity)

}
