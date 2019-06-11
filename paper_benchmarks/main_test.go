package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/immesys/wave/consts"
	exapi "github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/stretchr/testify/require"
)

var prof *os.File

func init() {
	f, err := os.Create("cpux.out")
	if err != nil {
		panic(err)
	}
	prof = f
}
func TestRTreeSimpleExisting(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "1", 1)
	tg.BuildCompare(t, "a", "1", 1, 1)
}

func TGraph(t testing.TB, outdegree int, depth int) {
	tg := TG()
	last_tier := []string{"ns"}
	idx := 0
	for d := 0; d < depth; d++ {
		next_tier := []string{}
		for _, lt := range last_tier {
			for od := 0; od < outdegree; od++ {
				nt := fmt.Sprintf("%d", idx)
				idx++
				next_tier = append(next_tier, nt)
				tg.Edge(t, lt, nt, "1", 100)
			}
		}
		last_tier = next_tier
	}
	//Graph built
	pprof.StartCPUProfile(prof)
	tg.BuildCompare(t, last_tier[0], "1", depth, 101-depth)
	pprof.StopCPUProfile()
	prof.Close()
	fmt.Printf("#,")
	tg.BuildCompare(t, last_tier[0], "1", depth, 101-depth)
}

// func TestD30(t *testing.T) {
// 	TGraph(t, 1, 30)
// }

func BenchmarkTestDepth(t *testing.B) {
	for i := 0; i < t.N; i++ {
		TGraph(t, 3, 5)
	}
}

func TestDepth(t *testing.T) {

	TGraph(t, 1, 60)

	/*
		for i := 0; i < 30; i++ {
			for j := 0; j < 10; j++ {
				fmt.Printf("%d,", 1+i)
				TGraph(t, 1, 1+i)

			}
		}
	*/
}

func BenchmarkDecryptAttestationVerifier(b *testing.B) {
	ctx := context.Background()
	srcpub, srcsec := createEntity(b)
	srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	dstpub, dstsec := createEntity(b)
	dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	permarr := []string{}
	pbits, err := strconv.ParseInt("11", 2, 64)
	require.NoError(b, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	policy := pb.RTreePolicy{
		Namespace:    srcpublish.Hash,
		Indirections: uint32(5),
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcpublish.Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	}
	pbpolicy := &pb.Policy{
		RTreePolicy: &policy,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: srcsec,
			},
			Location: &inmem,
		},
		BodyScheme:      exapi.BodySchemeWaveRef1,
		SubjectHash:     dstpublish.Hash,
		SubjectLocation: &inmem,
		Policy:          pbpolicy,
	})
	require.NoError(b, err)
	require.Nil(b, att.Error)
	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(b, err)
	require.Nil(b, pubresp.Error)
	srcpuber, err := iapi.ParseEntity(context.Background(), &iapi.PParseEntity{
		DER: srcpub,
	})
	require.NoError(b, err)
	dctx := iapi.NewKeyPoolDecryptionContext()
	dctx.SetWR1VerifierBodyKey(att.VerifierKey)
	dctx.AddEntity(srcpuber.Entity)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		par, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
			DER:               att.DER,
			DecryptionContext: dctx,
		})
		require.NoError(b, err)
		require.NotNil(b, par.Attestation)
		require.NotNil(b, par.Attestation.DecryptedBody)
	}
	_ = dstsec
}

func BenchmarkDecryptAttestationDirect(b *testing.B) {
	ctx := context.Background()
	srcpub, srcsec := createEntity(b)
	srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	dstpub, dstsec := createEntity(b)
	dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	permarr := []string{}
	pbits, err := strconv.ParseInt("11", 2, 64)
	require.NoError(b, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	policy := pb.RTreePolicy{
		Namespace:    srcpublish.Hash,
		Indirections: uint32(5),
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcpublish.Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	}
	pbpolicy := &pb.Policy{
		RTreePolicy: &policy,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: srcsec,
			},
			Location: &inmem,
		},
		BodyScheme:      exapi.BodySchemeWaveRef1,
		SubjectHash:     dstpublish.Hash,
		SubjectLocation: &inmem,
		Policy:          pbpolicy,
	})
	require.NoError(b, err)
	require.Nil(b, att.Error)
	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(b, err)
	require.Nil(b, pubresp.Error)
	dctx := iapi.NewKeyPoolDecryptionContext()
	es, err := iapi.ParseEntitySecrets(context.Background(), &iapi.PParseEntitySecrets{
		DER: dstsec,
	})
	require.NoError(b, err)
	srcpuber, err := iapi.ParseEntity(context.Background(), &iapi.PParseEntity{
		DER: srcpub,
	})
	require.NoError(b, err)
	dctx.AddEntitySecret(es.EntitySecrets, false)
	dctx.AddEntity(srcpuber.Entity)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		par, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
			DER:               att.DER,
			DecryptionContext: dctx,
		})
		require.NoError(b, err)
		require.NotNil(b, par.Attestation)
		require.NotNil(b, par.Attestation.DecryptedBody)
	}
	_ = dstsec
}

func BenchmarkDecryptAttestationOAQUE(b *testing.B) {
	ctx := context.Background()
	srcpub, srcsec := createEntity(b)
	srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	dstpub, dstsec := createEntity(b)
	dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	permarr := []string{}
	pbits, err := strconv.ParseInt("11", 2, 64)
	require.NoError(b, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	policy := pb.RTreePolicy{
		Namespace:    srcpublish.Hash,
		Indirections: uint32(5),
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcpublish.Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	}
	pbpolicy := &pb.Policy{
		RTreePolicy: &policy,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: srcsec,
			},
			Location: &inmem,
		},
		BodyScheme:      exapi.BodySchemeWaveRef1,
		SubjectHash:     dstpublish.Hash,
		SubjectLocation: &inmem,
		Policy:          pbpolicy,
	})
	require.NoError(b, err)
	require.Nil(b, att.Error)
	pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	require.NoError(b, err)
	require.Nil(b, pubresp.Error)
	dctx := iapi.NewKeyPoolDecryptionContext()
	es, err := iapi.ParseEntitySecrets(context.Background(), &iapi.PParseEntitySecrets{
		DER: dstsec,
	})
	require.NoError(b, err)
	srcpuber, err := iapi.ParseEntity(context.Background(), &iapi.PParseEntity{
		DER: srcpub,
	})
	require.NoError(b, err)
	dctx.AddEntitySecret(es.EntitySecrets, true)
	dctx.AddEntity(srcpuber.Entity)
	dctx.AddDomainVisibilityID([]byte(base64.URLEncoding.EncodeToString(srcpublish.Hash)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		par, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
			DER:               att.DER,
			DecryptionContext: dctx,
		})
		require.NoError(b, err)
		require.NotNil(b, par.Attestation)
		require.NotNil(b, par.Attestation.DecryptedBody)
	}
	_ = dstsec
}

func BenchmarkUpdatePerspectiveDirect(b *testing.B) {
	ctx := context.Background()
	dsts := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		srcpub, srcsec := createEntity(b)
		srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      srcpub,
			Location: &inmem,
		})
		require.NoError(b, err)

		dstpub, dstsec := createEntity(b)
		dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      dstpub,
			Location: &inmem,
		})
		require.NoError(b, err)
		dsts[i] = dstsec
		permarr := []string{}
		pbits, err := strconv.ParseInt("11", 2, 64)
		require.NoError(b, err)
		for i := 0; i < 64; i++ {
			if pbits&(1<<uint(i)) != 0 {
				permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
			}
		}
		policy := pb.RTreePolicy{
			Namespace:    srcpublish.Hash,
			Indirections: uint32(5),
			Statements: []*pb.RTreePolicyStatement{
				&pb.RTreePolicyStatement{
					PermissionSet: srcpublish.Hash,
					Permissions:   permarr,
					Resource:      "common/resource",
				},
			},
		}
		pbpolicy := &pb.Policy{
			RTreePolicy: &policy,
		}
		//Load the engine
		resp, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: dstsec,
				},
				Location: &inmem,
			},
		})
		require.NoError(b, err)
		require.Nil(b, resp.Error)
		eapi.WaitForSyncCompleteHack(&pb.SyncParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: dstsec,
				},
				Location: &inmem,
			},
		})

		_, _ = eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: srcsec,
				},
				Location: &inmem,
			},
			BodyScheme:      exapi.BodySchemeWaveRef1,
			SubjectHash:     dstpublish.Hash,
			SubjectLocation: &inmem,
			Policy:          pbpolicy,
			Publish:         true,
		})
	}
	b.ResetTimer()
	f, err := os.Create("resync_cpu.out")
	if err != nil {
		panic(err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		persp := &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dsts[i],
			},
		}
		resp, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
			Perspective: persp,
		})
		require.NoError(b, err)
		require.Nil(b, resp.Error)
		eapi.WaitForSyncCompleteHack(&pb.SyncParams{
			Perspective: persp,
		})
	}
	pprof.StopCPUProfile()
	f.Close()
}

func BenchmarkUpdatePerspectiveIndirect(b *testing.B) {
	ctx := context.Background()
	dsts := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		srcpub, srcsec := createEntity(b)
		srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      srcpub,
			Location: &inmem,
		})
		require.NoError(b, err)

		interpub, intersec := createEntity(b)
		interpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      interpub,
			Location: &inmem,
		})
		require.NoError(b, err)

		dstpub, dstsec := createEntity(b)
		dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      dstpub,
			Location: &inmem,
		})
		require.NoError(b, err)
		dsts[i] = dstsec
		permarr := []string{}
		pbits, err := strconv.ParseInt("11", 2, 64)
		require.NoError(b, err)
		for i := 0; i < 64; i++ {
			if pbits&(1<<uint(i)) != 0 {
				permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
			}
		}
		policy := pb.RTreePolicy{
			Namespace:    srcpublish.Hash,
			Indirections: uint32(5),
			Statements: []*pb.RTreePolicyStatement{
				&pb.RTreePolicyStatement{
					PermissionSet: srcpublish.Hash,
					Permissions:   permarr,
					Resource:      "common/resource",
				},
			},
		}
		pbpolicy := &pb.Policy{
			RTreePolicy: &policy,
		}
		_, _ = eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: intersec,
				},
				Location: &inmem,
			},
			BodyScheme:      exapi.BodySchemeWaveRef1,
			SubjectHash:     dstpublish.Hash,
			SubjectLocation: &inmem,
			Policy:          pbpolicy,
			Publish:         true,
		})
		resp, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: dstsec,
				},
				Location: &inmem,
			},
		})
		require.NoError(b, err)
		require.Nil(b, resp.Error)
		eapi.WaitForSyncCompleteHack(&pb.SyncParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: dstsec,
				},
				Location: &inmem,
			},
		})
		_, _ = eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: srcsec,
				},
				Location: &inmem,
			},
			BodyScheme:      exapi.BodySchemeWaveRef1,
			SubjectHash:     interpublish.Hash,
			SubjectLocation: &inmem,
			Policy:          pbpolicy,
			Publish:         true,
		})
	}
	b.ResetTimer()
	f, err := os.Create("resync2_cpu.out")
	if err != nil {
		panic(err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		persp := &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dsts[i],
			},
		}
		resp, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
			Perspective: persp,
		})
		require.NoError(b, err)
		require.Nil(b, resp.Error)
		eapi.WaitForSyncCompleteHack(&pb.SyncParams{
			Perspective: persp,
		})
	}
	pprof.StopCPUProfile()
	f.Close()
}

func BenchmarkCreateAttestation(b *testing.B) {
	ctx := context.Background()
	srcpub, srcsec := createEntity(b)
	srcpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	dstpub, _ := createEntity(b)
	dstpublish, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstpub,
		Location: &inmem,
	})
	require.NoError(b, err)

	permarr := []string{}
	pbits, err := strconv.ParseInt("11", 2, 64)
	require.NoError(b, err)
	for i := 0; i < 64; i++ {
		if pbits&(1<<uint(i)) != 0 {
			permarr = append(permarr, fmt.Sprintf("%x", 1<<uint(i)))
		}
	}
	policy := pb.RTreePolicy{
		Namespace:    srcpublish.Hash,
		Indirections: uint32(5),
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcpublish.Hash,
				Permissions:   permarr,
				Resource:      "common/resource",
			},
		},
	}
	pbpolicy := &pb.Policy{
		RTreePolicy: &policy,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: srcsec,
				},
				Location: &inmem,
			},
			BodyScheme:      exapi.BodySchemeWaveRef1,
			SubjectHash:     dstpublish.Hash,
			SubjectLocation: &inmem,
			Policy:          pbpolicy,
		})
		//fmt.Printf("attestation size: %d (%d)\n", len(r.DER), len(r.DER)/1024)
	}
}

func BenchmarkCreateEntity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = createEntity(b)
	}
}

func BenchmarkOAQUEE2EE(b *testing.B) {
	ctx := context.Background()
	srcPublic, srcSecret := createEntity(b)
	dstPublic, dstSecret := createEntity(b)
	_ = dstSecret
	srcpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcPublic,
		Location: &inmem,
	})
	_ = srcpub
	dstpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstPublic,
		Location: &inmem,
	})
	_ = dstpub
	_ = srcSecret
	require.NoError(b, err)
	msg := make([]byte, 512)
	rand.Read(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrv, err := eapi.EncryptMessage(ctx, &pb.EncryptMessageParams{
			Content:           msg,
			Namespace:         srcpub.Hash,
			NamespaceLocation: &inmem,
			Resource:          "foo/bar",
		})
		require.NoError(b, err)
		require.Nil(b, encrv.Error)
	}

}

func BenchmarkE2EEDecrypt(t *testing.B) {
	ctx := context.Background()
	srcPublic, srcSecret := createEntity(t)
	dstPublic, dstSecret := createEntity(t)
	_ = dstSecret
	srcpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcPublic,
		Location: &inmem,
	})
	_ = srcpub
	dstpub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstPublic,
		Location: &inmem,
	})
	_ = dstpub
	require.NoError(t, err)
	// srcdec, uerr := multihash.Decode(srcpub.Hash)
	// require.NoError(t, uerr)
	// dstdec, uerr := multihash.Decode(dstpub.Hash)
	// require.NoError(t, uerr)
	srcperspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        srcSecret,
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	dstperspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        dstSecret,
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	msg := make([]byte, 512)
	rand.Read(msg)
	encrv, err := eapi.EncryptMessage(ctx, &pb.EncryptMessageParams{
		Content:           msg,
		Namespace:         srcpub.Hash,
		NamespaceLocation: &inmem,
		Resource:          "foo/bar",
	})
	require.NoError(t, err)
	require.Nil(t, encrv.Error)

	//---------
	policy := pb.RTreePolicy{
		Namespace:    srcpub.Hash,
		Indirections: 5,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: []byte(consts.WaveBuiltinPSETBytes),
				Permissions:   []string{consts.WaveBuiltinE2EE},
				Resource:      "foo/*",
			},
		},
	}
	//policy.VisibilityURI = iapi.Partition("foo", "bar")

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective:     srcperspective,
		BodyScheme:      exapi.BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			RTreePolicy: &policy,
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: att.DER,
	})
	fmt.Printf("==== SYNCING DESTINATION GRAPH ====\n")
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: dstperspective,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: dstperspective,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete\n")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		decrv, err := eapi.DecryptMessage(ctx, &pb.DecryptMessageParams{
			Perspective: dstperspective,
			Ciphertext:  encrv.Ciphertext,
		})
		_ = decrv
		_ = err
	}

}
