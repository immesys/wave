package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/paper_benchmarks/scenario/common"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
)

var waveconn *eapi.EAPI

func GetPolicy(authinfo []byte) *common.Policy {
	resp, err := waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER: authinfo,
	})
	if err != nil {
		panic(err)
	}
	if resp.Error != nil {
		panic(resp.Error.Message)
	}
	rv := &common.Policy{}
	for _, st := range resp.Result.Policy.RTreePolicy.Statements {
		rv.Permissions = append(rv.Permissions, st.Permissions...)
		rv.Resources = append(rv.Resources, st.Resource)
	}
	return rv
}

func Init() {
	llsdb, err := lls.NewLowLevelStorage("/tmp/database")
	if err != nil {
		panic(err)
	}
	go memoryserver.Main()
	time.Sleep(100 * time.Millisecond)
	cfg := make(map[string]map[string]string)
	cfg["default"] = make(map[string]string)
	cfg["default"]["provider"] = "http_v1"
	cfg["default"]["url"] = "http://localhost:8080/v1"
	si, err := overlay.NewOverlay(cfg)
	if err != nil {
		fmt.Printf("storage overlay error: %v\n", err)
		os.Exit(1)
	}
	iapi.InjectStorageInterface(si)
	ws := poc.NewPOC(llsdb)
	waveconn = eapi.NewEAPI(ws)
}

func MakePolicy() []byte {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if src.Error != nil {
		panic(src.Error.Message)
	}
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if dst.Error != nil {
		panic(dst.Error.Message)
	}
	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: src.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	if srcresp.Error != nil {
		panic(srcresp.Error.Message)
	}
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: dst.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	if dstresp.Error != nil {
		panic(dstresp.Error.Message)
	}
	fmt.Printf("srcr: %x\n", srcresp.Hash)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: dst.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 4,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	attpub, err := waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}
	if attpub.Error != nil {
		panic(attpub.Error.Message)
	}
	waveconn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
	})
	err = waveconn.WaitForSyncCompleteHack(&pb.SyncParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		SubjectHash: dstresp.Hash,
		Namespace:   srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	return proofresp.ProofDER
}

func MakePolicy3() []byte {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if src.Error != nil {
		panic(src.Error.Message)
	}
	i1, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	i2, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if dst.Error != nil {
		panic(dst.Error.Message)
	}
	fmt.Printf("Src: %x\n", src.Hash)
	fmt.Printf("i1: %x\n", i1.Hash)
	fmt.Printf("i2: %x\n", i2.Hash)
	fmt.Printf("dst: %x\n", dst.Hash)

	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: src.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	if srcresp.Error != nil {
		panic(srcresp.Error.Message)
	}
	i1resp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: i1.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	i2resp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: i2.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: dst.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	if dstresp.Error != nil {
		panic(dstresp.Error.Message)
	}
	fmt.Printf("srcr: %x\n", srcresp.Hash)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: i1resp.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 3,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	_, err = waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}

	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: i1.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: i2resp.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 3,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	_, err = waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}

	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: i2.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: dstresp.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 3,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	_, err = waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}

	waveconn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
	})
	err = waveconn.WaitForSyncCompleteHack(&pb.SyncParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		SubjectHash: dstresp.Hash,
		Namespace:   srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	return proofresp.ProofDER
}

func main() {
	//
	// then := time.Now()
	// pol := GetPolicy(proof)
	// fmt.Printf("delta %s\n", time.Since(then))
	// spew.Dump(pol)
}
