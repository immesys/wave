package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dgraph-io/badger"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/coniks"
	_ "github.com/google/trillian/merkle/maphasher"
	_ "github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"github.com/immesys/wave/storage/simplehttp"
	"github.com/immesys/wave/storage/vldmstorage3/vldmpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type Config struct {
	TargetPublicKey   string
	TargetAddress     string
	Peers             []string
	PeerListenAddress string
	OutputFile        string
	DatabasePath      string
	MapServer         string
}

type adt struct {
	cfg         *Config
	peers       map[string]struct{}
	db          *badger.DB
	state       *state
	statemu     sync.Mutex
	tgt         vldmpb.VLDMClient
	mapClient   trillian.TrillianMapClient
	adminClient trillian.TrillianAdminClient

	mapTree *trillian.Tree
	logTree *trillian.Tree

	mapVerifier *client.MapVerifier
	logVerifier *client.LogVerifier

	vfile *os.File
}

type state struct {
	//This is for OUR map
	MapTreeId         int64
	OpLogIndex        int64
	RootLogIndex      int64
	SignedOpLogHead   []byte
	OpLogHead         *types.LogRootV1
	SignedRootLogHead []byte
	RootLogHead       *types.LogRootV1
}

func NewAuditor(configfile string) *adt {
	rv := &adt{cfg: &Config{}}
	_, err := toml.DecodeFile(configfile, rv.cfg)
	if err != nil {
		fmt.Printf("could not load config file: %v\n", err)
		os.Exit(1)
	}
	rv.cfg.TargetPublicKey = strings.TrimSpace(rv.cfg.TargetPublicKey)

	rv.vfile, err = os.OpenFile(rv.cfg.OutputFile, os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("could not open violation file: %v\n", err)
		os.Exit(1)
	}

	opts := badger.DefaultOptions
	opts.Dir = rv.cfg.DatabasePath
	opts.ValueDir = rv.cfg.DatabasePath
	db, err := badger.Open(opts)
	if err != nil {
		fmt.Printf("could not open database: %v\n", err)
		os.Exit(1)
	}
	rv.db = db
	//Load peers from config file
	rv.peers = make(map[string]struct{})
	for _, p := range rv.cfg.Peers {
		rv.peers[p] = struct{}{}
	}

	//Load peers from database
	err = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("peers/")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			v, err := item.Value()
			if err != nil {
				return err
			}
			rv.peers[string(v)] = struct{}{}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("database error: %v\n", err)
		os.Exit(1)
	}

	pubk, _ := pem.Decode([]byte(rv.cfg.TargetPublicKey))
	if pubk == nil {
		panic(fmt.Sprintf("bad public key %q", rv.cfg.TargetPublicKey))
	}

	//Map
	rv.mapTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "WAVE Storage map",
		Description:        "Storage of attestations and entities for WAVE",
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	rv.mapVerifier, err = client.NewMapVerifierFromTree(rv.mapTree)
	if err != nil {
		panic(err)
	}
	//Map root log
	rv.logTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "OPERATIONS",
		Description:        "for WAVE",
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	rv.logVerifier, err = client.NewLogVerifierFromTree(rv.logTree)
	if err != nil {
		panic(err)
	}

	rv.dialTrillian()
	rv.LoadStateFromDB()
	return rv
}

func (a *adt) dialTrillian() {
	mapconn, err := grpc.Dial(a.cfg.MapServer, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	adm := trillian.NewTrillianAdminClient(mapconn)
	a.adminClient = adm
	vmap := trillian.NewTrillianMapClient(mapconn)
	a.mapClient = vmap
}
func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: auditor <configfile>\n")
		os.Exit(1)
	}
	a := NewAuditor(os.Args[1])
	a.dialTarget()
	go a.StartServer()
	go a.Gossip()
	a.ScanTarget()
}

func (a *adt) dialTarget() {
	targetconn, err := grpc.Dial(a.cfg.TargetAddress, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	tgt := vldmpb.NewVLDMClient(targetconn)
	a.tgt = tgt
}
func (a *adt) StartServer() {
	grpcServer := grpc.NewServer()
	l, err := net.Listen("tcp", a.cfg.PeerListenAddress)
	if err != nil {
		panic(err)
	}
	vldmpb.RegisterAuditorServer(grpcServer, a)
	go grpcServer.Serve(l)
}

func (a *adt) GetPeers(ctx context.Context, p *vldmpb.GetPeersParams) (*vldmpb.GetPeersResponse, error) {
	if p.Publickey != a.cfg.TargetPublicKey {
		return nil, grpc.Errorf(codes.InvalidArgument, "this auditor is for a different server")
	}
	peers := make([]string, 0, len(a.peers))
	for p, _ := range a.peers {
		peers = append(peers, p)
	}
	return &vldmpb.GetPeersResponse{
		Hosts: peers,
	}, nil
}

func (a *adt) UpdateOpLog() {
	resp, err := a.tgt.GetLogHead(context.Background(), &vldmpb.GetLogHeadParams{
		IsOperation: true,
	})
	if err != nil {
		panic(err)
	}
	ba := resp.TrillianSignedLogRoot
	slr := trillian.SignedLogRoot{}
	err = proto.Unmarshal(ba, &slr)
	if err != nil {
		panic(err)
	}
	if a.state.OpLogHead == nil {
		newroot, err := a.logVerifier.VerifyRoot(&types.LogRootV1{}, &slr, nil)
		if err != nil {
			a.logViolation("new root failed to validate, slr=%x\n", ba)
			os.Exit(1)
		}
		a.state.OpLogHead = newroot
		a.state.SignedOpLogHead = ba
		a.SaveStateToDB()
	} else if int64(a.state.OpLogHead.TreeSize) < slr.TreeSize {
		cresp, err := a.tgt.GetLogConsistency(context.Background(), &vldmpb.GetConsistencyParams{
			IsOperation: true,
			From:        int64(a.state.OpLogHead.TreeSize),
			To:          slr.TreeSize,
		})
		if err != nil {
			panic(err)
		}
		proof := trillian.Proof{}
		err = proto.Unmarshal(cresp.TrillianProof, &proof)
		if err != nil {
			panic(err)
		}
		newroot, err := a.logVerifier.VerifyRoot(a.state.OpLogHead, &slr, proof.Hashes)
		if err != nil {
			a.logViolation("operation log is inconsistent. previous_oplog=%x new_oplog=%x\n", a.state.SignedOpLogHead, ba)
			os.Exit(1)
		}
		a.state.OpLogHead = newroot
		a.state.SignedOpLogHead = ba
		a.SaveStateToDB()
	}
}
func (a *adt) UpdateRootLog() {
	resp, err := a.tgt.GetLogHead(context.Background(), &vldmpb.GetLogHeadParams{
		IsOperation: false,
	})
	if err != nil {
		panic(err)
	}
	ba := resp.TrillianSignedLogRoot
	slr := trillian.SignedLogRoot{}
	err = proto.Unmarshal(ba, &slr)
	if err != nil {
		panic(err)
	}
	if a.state.RootLogHead == nil {
		newroot, err := a.logVerifier.VerifyRoot(&types.LogRootV1{}, &slr, nil)
		if err != nil {
			a.logViolation("new root failed to validate, srlr=%x\n", ba)
			os.Exit(1)
		}
		a.state.RootLogHead = newroot
		a.state.SignedRootLogHead = ba
		a.SaveStateToDB()
	} else if int64(a.state.RootLogHead.TreeSize) < slr.TreeSize {
		cresp, err := a.tgt.GetLogConsistency(context.Background(), &vldmpb.GetConsistencyParams{
			IsOperation: false,
			From:        int64(a.state.RootLogHead.TreeSize),
			To:          slr.TreeSize,
		})
		if err != nil {
			panic(err)
		}
		proof := trillian.Proof{}
		err = proto.Unmarshal(cresp.TrillianProof, &proof)
		if err != nil {
			panic(err)
		}
		newroot, err := a.logVerifier.VerifyRoot(a.state.RootLogHead, &slr, proof.Hashes)
		if err != nil {
			a.logViolation("root log is inconsistent. previous_rootlog=%x new_rootlog=%x\n", a.state.SignedRootLogHead, ba)
			os.Exit(1)
		}
		a.state.RootLogHead = newroot
		a.state.SignedRootLogHead = ba
		a.SaveStateToDB()
	}
}
func (a *adt) ScanTarget() {
	for {
		time.Sleep(1 * time.Second)
		a.statemu.Lock()
		//Update our log heads
		a.UpdateRootLog()
		a.UpdateOpLog()

		if a.state.RootLogIndex == int64(a.state.RootLogHead.TreeSize-1) {
			a.statemu.Unlock()
			continue
		}
		//For every new entry in the root log, update our map to match and verify
		for i := a.state.RootLogIndex + 1; i < int64(a.state.RootLogHead.TreeSize); i++ {
			maproot, err := a.tgt.GetLogItem(context.Background(), &vldmpb.GetLogItemParams{
				IsOperation: false,
				Index:       i,
				Size:        int64(a.state.RootLogHead.TreeSize),
			})
			if err != nil {
				panic(err)
			}
			te := trillian.GetEntryAndProofResponse{}
			err = proto.Unmarshal(maproot.TrillianGetEntryAndProofResponse, &te)
			if err != nil {
				panic(err)
			}
			err = a.logVerifier.VerifyInclusionAtIndex(a.state.RootLogHead, te.Leaf.LeafValue, i, te.Proof.Hashes)
			if err != nil {
				a.logViolation("root log lied about inclusion: %v\n", err)
				os.Exit(1)
			}
			smr := trillian.SignedMapRoot{}
			err = proto.Unmarshal(te.Leaf.LeafValue, &smr)
			if err != nil {
				panic(err)
			}
			a.updateAndVerifyMap(i, &smr, te.Leaf.LeafValue)
			a.state.RootLogIndex = i
			a.SaveStateToDB()
		}
		a.storeVerified(a.state.RootLogHead.RootHash)
		a.statemu.Unlock()
	}
}
func (a *adt) Gossip() {
	for {
		for p, _ := range a.peers {
			peerconn, err := grpc.Dial(p, grpc.WithInsecure(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
			if err != nil {
				fmt.Printf("peer dial error: %v\n", err)
				continue
			}
			peer := vldmpb.NewAuditorClient(peerconn)
			peer.SubmitLogRoot(context.Background(), &vldmpb.SubmitLogRootParams{
				SignedLogRoot: a.state.SignedRootLogHead,
			})
			peerconn.Close()
		}
		time.Sleep(30 * time.Minute)
	}
}

type PromiseObject struct {
	Promise *simplehttp.MergePromise
	Seals   []*simplehttp.V1CertifierSeal
	Key     []byte
	Value   []byte
}

func (a *adt) updateAndVerifyMap(mapindex int64, expected *trillian.SignedMapRoot, expectedbin []byte) {
	mr := types.MapRootV1{}
	err := mr.UnmarshalBinary(expected.MapRoot)
	if err != nil {
		panic(err)
	}
	met := vldmpb.MapperMetadata{}
	err = proto.Unmarshal(mr.Metadata, &met)
	if err != nil {
		panic(err)
	}
	newindex := met.HighestFullyCompletedSeq
	lastindex := a.state.OpLogIndex
	ops := []*trillian.MapLeaf{}
	for i := lastindex; i <= newindex; i++ {
		item, err := a.tgt.GetLogItem(context.Background(), &vldmpb.GetLogItemParams{
			IsOperation: true,
			Index:       i,
			Size:        int64(a.state.OpLogHead.TreeSize),
		})
		if err != nil {
			panic(err)
		}
		te := trillian.GetEntryAndProofResponse{}
		err = proto.Unmarshal(item.TrillianGetEntryAndProofResponse, &te)
		if err != nil {
			panic(err)
		}
		err = a.logVerifier.VerifyInclusionAtIndex(a.state.OpLogHead, te.Leaf.LeafValue, i, te.Proof.Hashes)
		if err != nil {
			a.logViolation("op log lied about inclusion\n")
			os.Exit(1)
		}
		mp := &PromiseObject{}
		err = json.Unmarshal(te.Leaf.LeafValue, &mp)
		if err != nil {
			panic(err)
		}
		ops = append(ops, &trillian.MapLeaf{
			Index:     mp.Key,
			LeafValue: mp.Value,
		})
	}
	resp, err := a.mapClient.SetLeaves(context.Background(), &trillian.SetMapLeavesRequest{
		MapId:    a.state.MapTreeId,
		Leaves:   ops,
		Metadata: mr.Metadata,
	})
	if err != nil {
		panic(err)
	}
	replicamaproot := &types.MapRootV1{}
	err = replicamaproot.UnmarshalBinary(resp.MapRoot.MapRoot)
	if err != nil {
		panic(err)
	}
	if bytes.Equal(replicamaproot.RootHash, mr.RootHash) {
		fmt.Printf("MAP ROOT %d VALIDATED SUCCESSFULLY\n", mapindex)
	} else {
		a.logViolation("map root does not match smr=%x\n", expectedbin)
		os.Exit(1)
	}
	//Save the root log index
	a.state.OpLogIndex = newindex
}

func (a *adt) SubmitLogRoot(ctx context.Context, p *vldmpb.SubmitLogRootParams) (*vldmpb.SubmitLogRootResponse, error) {
	lr := trillian.SignedLogRoot{}
	err := proto.Unmarshal(p.SignedLogRoot, &lr)
	if err != nil {
		return nil, fmt.Errorf("bad signed log root\n")
	}

	//Verify the signature manually. We don't care about SLR from different keys
	logroot, err := tcrypto.VerifySignedLogRoot(a.logVerifier.PubKey, a.logVerifier.SigHash, &lr)
	if err != nil {
		return nil, fmt.Errorf("bad signature: %v\n", err)
	}

	fmt.Printf("received root log from peer\n")
	if a.haveWeVerified(logroot.RootHash) {
		return &vldmpb.SubmitLogRootResponse{
			Trustworthy: true,
		}, nil
	}
	//Need to perform a quick consistency check
	if logroot.TreeSize >= a.state.RootLogHead.TreeSize {
		a.UpdateRootLog()
	}
	a.statemu.Lock()
	defer a.statemu.Unlock()
	if logroot.TreeSize == a.state.RootLogHead.TreeSize {
		//must equal
		if !bytes.Equal(logroot.RootHash, a.state.RootLogHead.RootHash) {
			a.logViolation("peer SLR with same tree size has different hash: peer=%x ours=%x\n", p.SignedLogRoot, a.state.SignedRootLogHead)
			os.Exit(1)
		}
	} else if logroot.TreeSize > a.state.RootLogHead.TreeSize {
		a.logViolation("received valid log root with greater tree size received=%x ours=%x\n", p.SignedLogRoot, a.state.SignedRootLogHead)
		os.Exit(1)
	} else {
		//Passed is smaller
		cresp, err := a.tgt.GetLogConsistency(context.Background(), &vldmpb.GetConsistencyParams{
			From: int64(logroot.TreeSize),
			To:   int64(a.state.RootLogHead.TreeSize),
		})
		if err != nil {
			panic(err)
		}
		proof := trillian.Proof{}
		err = proto.Unmarshal(cresp.TrillianProof, &proof)
		if err != nil {
			panic(err)
		}
		signedcurrenthead := trillian.SignedLogRoot{}
		err = proto.Unmarshal(a.state.SignedRootLogHead, &signedcurrenthead)
		if err != nil {
			panic(err)
		}
		_, err = a.logVerifier.VerifyRoot(logroot, &signedcurrenthead, proof.Hashes)
		if err != nil {
			a.logViolation("peer SLR is inconsistent with ours: peer=%x ours=%x\n", p.SignedLogRoot, a.state.SignedRootLogHead)
			os.Exit(1)
		}
	}
	return &vldmpb.SubmitLogRootResponse{
		Trustworthy: true,
	}, nil
}

func (a *adt) logViolation(f string, args ...interface{}) {
	msg := fmt.Sprintf(f, args...)
	fmt.Printf("VIOLATION: %s\n", msg)
	a.vfile.Write([]byte(msg))
	a.vfile.Sync()
}
