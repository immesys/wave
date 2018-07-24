package eapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/bouk/monkey"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	multihash "github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

var eapi *EAPI
var inmem pb.Location

func init() {
	go memoryserver.Main()
	time.Sleep(100 * time.Millisecond)
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	//inmem := iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	inmem.LocationURI = &pb.LocationURI{
		URI:     "http://localhost:8080/v1",
		Version: 1,
	}
	inmem.AgentLocation = "inmem"
	si, err := overlay.NewOverlay(cfg)
	if err != nil {
		panic(err)
	}
	iapi.InjectStorageInterface(si)

	tdir, _ := ioutil.TempDir("", "lls")
	llsdb, err := lls.NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
	ws := poc.NewPOC(llsdb)
	eapi = NewEAPI(ws)
}

func TestCreateEntity(t *testing.T) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	require.NotNil(t, rv.PublicDER)
	require.NotNil(t, rv.SecretDER)
	require.Nil(t, rv.Error)
}

func TestCreateEntityNoPassphrase(t *testing.T) {
	ctx := context.Background()
	src, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{})
	require.NoError(t, err)
	require.NotNil(t, src.PublicDER)
	require.NotNil(t, src.SecretDER)
	//Try create an attestation with it to verify it works
	_, _, otherhash := createAndPublishEntity(t)
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     otherhash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	require.NotZero(t, len(att.DER))
}

func createEntity(t *testing.T) (public []byte, secret []byte) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
	//SecretPassphrase: "password",
	})
	require.NoError(t, err)
	return rv.PublicDER, rv.SecretDER
}
func createAndPublishEntity(t *testing.T) (public []byte, secret []byte, hash []byte) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
	//SecretPassphrase: "password",
	})
	require.NoError(t, err)
	rvhash, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      rv.PublicDER,
		Location: &inmem,
	})
	return rv.PublicDER, rv.SecretDER, rvhash.Hash
}
func TestPublishCorruptEntity(t *testing.T) {
	ctx := context.Background()
	rv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	canonical, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      rv.PublicDER,
		Location: &inmem,
	})
	//We expect no err, but rv.Error non nil
	der := rv.PublicDER
	require.NoError(t, err)
	require.Nil(t, canonical.Error)
	for i := 0; i < len(rv.PublicDER); i++ {
		for bit := 1; bit <= 0x80; bit <<= 1 {
			cp := make([]byte, len(der))
			copy(cp, der)
			cp[i] ^= byte(bit)
			resp, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
				DER:      cp,
				Location: &inmem,
			})
			require.NoError(t, err)
			if resp.Error == nil {
				require.EqualValues(t, canonical.Hash, resp.Hash)
			}
		}
	}
}
func TestCorruptAttestationPublish(t *testing.T) {
	//Attestations are big now. This takes forever
	t.Skip()
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
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	der := att.DER
	canonical, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      der,
		Location: &inmem,
	})
	//Test that for every single bit in the attestation, flipping it causes an error
	attlen := len(der)
	for i := 0; i < attlen; i++ {
		for bit := 1; bit <= 0x80; bit <<= 1 {
			cp := make([]byte, len(der))
			copy(cp[:], der)
			cp[i] ^= byte(bit)
			resp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
				DER:      cp,
				Location: &inmem,
			})
			//spew.Dump(resp)
			require.NoError(t, err)
			//require.NotNil(t, resp.Error, "byte %d bit %d was flipped without causing an error", i, bit)
			if resp.Error == nil {
				require.EqualValues(t, canonical.Hash, resp.Hash)
				//fmt.Printf("%d.%d OK\n", i, bit)
			} else {
				require.NotNil(t, resp.Error)
				//fmt.Printf("%d.%d %s\n", i, bit, resp.Error.Message)
			}
		}
	}
}

func TestWrongPassphrase(t *testing.T) {
	ctx := context.Background()
	srcrv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	_, err = eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      srcrv.PublicDER,
		Location: &inmem,
	})
	require.NoError(t, err)
	dstrv, err := eapi.CreateEntity(ctx, &pb.CreateEntityParams{
		SecretPassphrase: "password",
	})
	require.NoError(t, err)
	dstrvhash, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dstrv.PublicDER,
		Location: &inmem,
	})
	require.NoError(t, err)

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcrv.SecretDER,
				Passphrase: []byte("wrongpassphrase"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstrvhash.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, att.Error)
}

func TestE2EEDirectEncryption(t *testing.T) {
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
		Perspective:     srcperspective,
		Content:         msg,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
	})
	require.NoError(t, err)
	require.Nil(t, encrv.Error)

	decrv, err := eapi.DecryptMessage(ctx, &pb.DecryptMessageParams{
		Perspective: dstperspective,
		Ciphertext:  encrv.Ciphertext,
	})
	require.NoError(t, err)
	require.Nil(t, decrv.Error)
	require.Equal(t, decrv.Content, msg)
}

func TestE2EEOAQUEEncryptionNS(t *testing.T) {
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
			DER: srcSecret,
		},
		Location: &inmem,
	}
	dstperspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: dstSecret,
		},
		Location: &inmem,
	}
	msg := make([]byte, 512)
	rand.Read(msg)
	encrv, err := eapi.EncryptMessage(ctx, &pb.EncryptMessageParams{
		Perspective:       dstperspective,
		Content:           msg,
		Namespace:         srcpub.Hash,
		NamespaceLocation: &inmem,
		Partition:         [][]byte{[]byte("foo"), []byte("bar")},
	})
	require.NoError(t, err)
	require.Nil(t, encrv.Error)

	decrv, err := eapi.DecryptMessage(ctx, &pb.DecryptMessageParams{
		Perspective: srcperspective,
		Ciphertext:  encrv.Ciphertext,
	})
	require.NoError(t, err)
	require.Nil(t, decrv.Error)
	require.Equal(t, decrv.Content, msg)
}

func TestE2EEOAQUEEncryptionDelegated(t *testing.T) {
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
		Perspective:       srcperspective,
		Content:           msg,
		Namespace:         srcpub.Hash,
		NamespaceLocation: &inmem,
		Partition:         [][]byte{[]byte("foo"), []byte("bar")},
	})
	require.NoError(t, err)
	require.Nil(t, encrv.Error)

	//---------
	policy := pb.RTreePolicy{
		Namespace:    srcpub.Hash,
		Indirections: 5,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcpub.Hash,
				Permissions:   []string{"foo"},
				Resource:      "foo/bar",
			},
		},
	}
	policy.VisibilityURI = [][]byte{[]byte("foo"), []byte("bar")}

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective:     srcperspective,
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			RTreePolicy: &policy,
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
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

	//---------------------
	// nsent, _ := iapi.ParseEntitySecrets(ctx, &iapi.PParseEntitySecrets{
	// 	DER:        srcSecret,
	// 	Passphrase: iapi.String("password"),
	// })
	// k, _ := nsent.EntitySecrets.WR1BodyKey(ctx, iapi.XXSlots)
	//
	decrv, err := eapi.DecryptMessage(ctx, &pb.DecryptMessageParams{
		Perspective: dstperspective,
		Ciphertext:  encrv.Ciphertext,
	})

	// _, err = k.DecryptMessage(ctx, iapi.XXCiphertext)
	// if err == nil {
	// 	fmt.Printf("SUCCEEDED XX in decrypting message with sneaky key\n")
	// } else {
	// 	fmt.Printf("END THING XX failed to decrypt message\n")
	// }
	// fmt.Printf("YY decrypt as %s\n", nsent.EntitySecrets.Entity.Keccak256HI().MultihashString())
	// k2, _ := nsent.EntitySecrets.WR1BodyKey(ctx, iapi.YYSlots)
	// _, err = k2.DecryptMessage(ctx, iapi.YYCiphertext)
	// if err == nil {
	// 	fmt.Printf("SUCCEEDED YY in decrypting message with sneaky key\n")
	// } else {
	// 	fmt.Printf("END THING YY failed to decrypt message\n")
	// }

	require.NoError(t, err)
	require.Nil(t, decrv.Error)
	require.Equal(t, decrv.Content, msg)
}

func TestCreateAttestationWithLookup(t *testing.T) {
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
	srcdec, uerr := multihash.Decode(srcpub.Hash)
	require.NoError(t, uerr)
	fmt.Printf("SRC hash is: %x\n", srcdec.Digest)
	dstdec, uerr := multihash.Decode(dstpub.Hash)
	require.NoError(t, uerr)
	fmt.Printf("DST hash is: %x\n", dstdec.Digest)
	dstperspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        dstSecret,
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
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
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("==== STARTING LOOKUP IN DESTINATION GRAPH ====\n")
	lookupresponse, err := eapi.LookupAttestations(ctx, &pb.LookupAttestationsParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        dstSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		ToEntity: dstpub.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, lookupresponse.Error)
	require.EqualValues(t, 1, len(lookupresponse.Results))
	res := lookupresponse.Results[0]
	require.NotNil(t, res.Body)
	require.EqualValues(t, &inmem, res.SubjectLocation)
	require.EqualValues(t, dstpub.Hash, res.SubjectHash)
	require.EqualValues(t, true, res.Validity.Valid)
	require.EqualValues(t, false, res.Validity.SrcInvalid)
	require.EqualValues(t, false, res.Validity.DstInvalid)
	require.EqualValues(t, false, res.Validity.DstInvalid)
	require.EqualValues(t, false, res.Validity.Expired)
	require.EqualValues(t, false, res.Validity.Malformed)
	require.EqualValues(t, false, res.Validity.NotDecrypted)
}

func TestCreateAttestationExpiryNonIntersect(t *testing.T) {
	//This is a little wierd. We want to have
	// A->B->C.
	// BC is granted in present time
	// AB is granted in the future
	// graph is synced to learn BC
	// time is set to future
	// graph sync
	// see if AB is decrypted
	tPresent := time.Now().Add(-24 * time.Hour)
	tFuture := time.Now().Add(180 * 24 * time.Hour)
	ctx := context.Background()
	srcPublic, srcSecret := createEntity(t)
	dstPublic, dstSecret := createEntity(t)
	dst2Public, dst2Secret := createEntity(t)
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
	dst2pub, err := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      dst2Public,
		Location: &inmem,
	})
	_ = dst2pub
	require.NoError(t, err)
	srcdec, uerr := multihash.Decode(srcpub.Hash)
	require.NoError(t, uerr)
	fmt.Printf("SRC hash is: %x\n", srcdec.Digest)
	dstdec, uerr := multihash.Decode(dstpub.Hash)
	require.NoError(t, uerr)
	fmt.Printf("DST hash is: %x\n", dstdec.Digest)
	dst2perspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        dst2Secret,
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}

	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        dstSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dst2pub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
		ValidFrom:  tPresent.UnixNano() / 1e6,
		ValidUntil: tPresent.Add(30*24*time.Hour).UnixNano() / 1e6,
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
	})
	fmt.Printf("==== SYNCING DESTINATION GRAPH ====\n")
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: dst2perspective,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: dst2perspective,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	//Now publish AB

	att, err = eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
		ValidFrom:  tFuture.UnixNano() / 1e6,
		ValidUntil: tFuture.Add(30*24*time.Hour).UnixNano() / 1e6,
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
	})

	//Shift time
	patch := monkey.Patch(time.Now, func() time.Time { return tFuture })
	defer patch.Unpatch()

	//Resync
	fmt.Printf("==== SYNCING DESTINATION GRAPH ====\n")
	rv, err = eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: dst2perspective,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: dst2perspective,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("==== STARTING LOOKUP IN DESTINATION GRAPH ====\n")
	lookupresponse, err := eapi.LookupAttestations(ctx, &pb.LookupAttestationsParams{
		Perspective: dst2perspective,
		ToEntity:    dstpub.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, lookupresponse.Error)
	require.EqualValues(t, 0, len(lookupresponse.Results))
}

func TestAttestationLabelledToActive(t *testing.T) {
	ctx := context.Background()
	ap, as := createEntity(t)
	bp, bs := createEntity(t)
	cp, cs := createEntity(t)

	apub, _ := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      ap,
		Location: &inmem,
	})
	bpub, _ := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      bp,
		Location: &inmem,
	})
	cpub, _ := eapi.PublishEntity(ctx, &pb.PublishEntityParams{
		DER:      cp,
		Location: &inmem,
	})
	_ = cpub

	policy := &pb.Policy{
		RTreePolicy: &pb.RTreePolicy{
			Namespace:    apub.Hash,
			Indirections: 5,
			Statements: []*pb.RTreePolicyStatement{
				&pb.RTreePolicyStatement{
					PermissionSet: apub.Hash,
					Permissions:   []string{"foo"},
					Resource:      "bar",
				},
			},
		}}
	policy.RTreePolicy.VisibilityURI = iapi.Partition("p1", "p2")
	at1, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: as,
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     bpub.Hash,
		SubjectLocation: &inmem,
		Policy:          policy,
	})
	require.NoError(t, err)
	require.Nil(t, at1.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      at1.DER,
		Location: &inmem,
	})

	policy.RTreePolicy.VisibilityURI = iapi.Partition("p1", "p2", "p3")
	at2, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: bs,
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     cpub.Hash,
		SubjectLocation: &inmem,
		Policy:          policy,
	})
	require.NoError(t, err)
	require.Nil(t, at2.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      at2.DER,
		Location: &inmem,
	})

	fmt.Printf("==== SYNCING DESTINATION GRAPH ====\n")
	cper := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER: cs,
		},
		Location: &inmem,
	}
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: cper,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	wsync := func() {
		for {
			ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
				Perspective: cper,
			})
			require.NoError(t, err)
			require.Nil(t, ss.Error)
			//fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
			if ss.CompletedSyncs == ss.TotalSyncRequests {
				//fmt.Printf("Syncs complete")
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	wsync()
	fmt.Printf("==== FIRST SYNC COMPLETE ====\n")

	lu1, err := eapi.LookupAttestations(ctx, &pb.LookupAttestationsParams{
		Perspective: cper,
		ToEntity:    bpub.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, lu1.Error)
	require.EqualValues(t, 0, len(lu1.Results))

	policy.RTreePolicy.VisibilityURI = iapi.Partition("p1", "p2")
	at3, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: bs,
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     cpub.Hash,
		SubjectLocation: &inmem,
		Policy:          policy,
	})
	require.NoError(t, err)
	require.Nil(t, at3.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      at3.DER,
		Location: &inmem,
	})

	rv, err = eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: cper,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	wsync()

	fmt.Printf("==== SECOND SYNC COMPLETE ====\n")

	//Try decrypt some ciphertexts with the problematic key

	lu2, err := eapi.LookupAttestations(ctx, &pb.LookupAttestationsParams{
		Perspective: cper,
		ToEntity:    bpub.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, lu2.Error)
	require.EqualValues(t, 1, len(lu2.Results))
}

func TestCreateAttestationWithExpiredLookup(t *testing.T) {
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
	dstperspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        dstSecret,
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        srcSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		BodyScheme:      BodySchemeWaveRef1,
		SubjectHash:     dstpub.Hash,
		SubjectLocation: &inmem,
		Policy: &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: 3,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, att.Error)
	eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER:      att.DER,
		Location: &inmem,
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
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("==== STARTING LOOKUP IN DESTINATION GRAPH ====\n")

	future := time.Date(2050, time.May, 19, 1, 2, 3, 4, time.UTC)
	patch := monkey.Patch(time.Now, func() time.Time { return future })
	defer patch.Unpatch()

	lookupresponse, err := eapi.LookupAttestations(ctx, &pb.LookupAttestationsParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        dstSecret,
				Passphrase: []byte("password"),
			},
			Location: &inmem,
		},
		ToEntity: dstpub.Hash,
	})
	require.NoError(t, err)
	require.Nil(t, lookupresponse.Error)
	require.EqualValues(t, 1, len(lookupresponse.Results))
	res := lookupresponse.Results[0]
	require.NotNil(t, res.Body)
	require.EqualValues(t, &inmem, res.SubjectLocation)
	require.EqualValues(t, dstpub.Hash, res.SubjectHash)
	require.EqualValues(t, false, res.Validity.Valid)
}

func TestBuildRTreeProof(t *testing.T) {
	ctx := context.Background()
	publics := make([][]byte, 9)
	secrets := make([][]byte, 9)
	pubs := make([]*pb.PublishEntityResponse, 9)
	for i := 0; i < 9; i++ {
		publics[i], secrets[i] = createEntity(t)
		var err error
		pubs[i], err = eapi.PublishEntity(ctx, &pb.PublishEntityParams{
			DER:      publics[i],
			Location: &inmem,
		})
		require.NoError(t, err)
	}
	perspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{
			DER:        secrets[8],
			Passphrase: []byte("password"),
		},
		Location: &inmem,
	}
	createAt := func(from int, to int, res string, ttl int) {
		policy := pb.RTreePolicy{
			Namespace:    pubs[0].Hash,
			Indirections: uint32(ttl),
			Statements: []*pb.RTreePolicyStatement{
				&pb.RTreePolicyStatement{
					PermissionSet: pubs[0].Hash,
					Permissions:   []string{"foo"},
					Resource:      res,
				},
			},
		}
		pbpolicy := &pb.Policy{
			RTreePolicy: &policy,
		}
		then := time.Now()
		att, err := eapi.CreateAttestation(ctx, &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER:        secrets[from],
					Passphrase: []byte("password"),
				},
				Location: &inmem,
			},
			BodyScheme:      BodySchemeWaveRef1,
			SubjectHash:     pubs[to].Hash,
			SubjectLocation: &inmem,
			Policy:          pbpolicy,
		})
		require.NoError(t, err)
		require.Nil(t, att.Error)
		fmt.Printf("XXX create took %s\n", time.Now().Sub(then))
		then = time.Now()
		pubresp, err := eapi.PublishAttestation(ctx, &pb.PublishAttestationParams{
			DER:      att.DER,
			Location: &inmem,
		})
		require.NoError(t, err)
		require.Nil(t, pubresp.Error)
		fmt.Printf("XXX publish took %s\n", time.Now().Sub(then))
	}
	createAt(0, 1, "a/b", 5)
	createAt(0, 2, "c/d", 5)
	createAt(1, 3, "a/b/c", 5)
	createAt(1, 4, "a/b", 5)
	createAt(4, 5, "a/b", 0)
	createAt(4, 6, "a/b", 5)
	createAt(6, 7, "a/b", 5)
	createAt(3, 8, "a/b", 5)
	createAt(5, 8, "a/b", 5)
	createAt(7, 8, "a/b", 5)
	fmt.Printf("==== SYNCING DESTINATION GRAPH ====\n")
	rv, err := eapi.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{
		Perspective: perspective,
	})
	require.NoError(t, err)
	require.Nil(t, rv.Error)
	//Spin until sync complete (but don't use wait because its hard to use)
	for {
		ss, err := eapi.SyncStatus(ctx, &pb.SyncParams{
			Perspective: perspective,
		})
		require.NoError(t, err)
		require.Nil(t, ss.Error)
		fmt.Printf("syncs %d/%d\n", ss.TotalSyncRequests, ss.CompletedSyncs)
		if ss.CompletedSyncs == ss.TotalSyncRequests {
			fmt.Printf("Syncs complete")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("==== STARTING BUILD IN DESTINATION GRAPH ====\n")

	resp, err := eapi.BuildRTreeProof(ctx, &pb.BuildRTreeParams{
		Perspective:    perspective,
		SubjectHash:    pubs[8].Hash,
		RtreeNamespace: pubs[0].Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: pubs[0].Hash,
				Permissions:   []string{"foo"},
				Resource:      "a/b",
			},
		},
	})
	_ = resp
	require.NoError(t, err)
	// require.EqualValues(t, 1, len(resp.Results))
	// require.EqualValues(t, 1, resp.Results[0].Policy.RTreePolicy.Indirections)
	// require.EqualValues(t, 5, len(resp.Results[0].Elements))
	// require.EqualValues(t, pubs[8].Hash, resp.Results[0].Elements[4].SubjectHash)
}
