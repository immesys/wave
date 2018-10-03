package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"github.com/immesys/wave/storage/vldmstorage2/pb"
)

const LogBatchSize = 280

var mapperLogClient *client.LogClient

func PerformOneMap(certifierIDs []string) (bool, error) {
	start := time.Now()
	getRootReq := &trillian.GetSignedMapRootRequest{MapId: TreeID_Map}
	getRootResp, err := vmap.GetSignedMapRoot(context.Background(), getRootReq)
	if err != nil {
		return false, err
	}

	var mapRoot types.MapRootV1
	if err := mapRoot.UnmarshalBinary(getRootResp.GetMapRoot().GetMapRoot()); err != nil {
		return false, err
	}

	mapperMetadata := &pb.MapperMetadata{}
	startEntry := int64(0)

	if len(mapRoot.Metadata) != 0 {

		if err := proto.Unmarshal(mapRoot.Metadata, mapperMetadata); err != nil {
			return false, fmt.Errorf("failed to unmarshal MapRoot.Metadata: %v", err)
		}

		startEntry = mapperMetadata.HighestFullyCompletedSeq + 1
	} else {
		fmt.Printf("bootstrapping first run\n")
	}
	fmt.Printf("Fetching entries [%d+] from log: ", startEntry)

	// Get the entries from the log:
	entryresp, err := logclient.GetLeavesByRange(context.Background(), &trillian.GetLeavesByRangeRequest{
		LogId:      TreeID_Op,
		StartIndex: startEntry,
		Count:      LogBatchSize,
	})
	if err != nil {
		return false, err
	}
	if len(entryresp.Leaves) == 0 {
		fmt.Printf("No entries from log\n")
		return false, nil
	} else {
		fmt.Printf("Found %d\n", len(entryresp.Leaves))
	}

	// Store updated map values:
	setReq := &trillian.SetMapLeavesRequest{
		MapId:  TreeID_Map,
		Leaves: make([]*trillian.MapLeaf, 0, len(entryresp.Leaves)),
	}

	endID := startEntry

	for _, l := range entryresp.Leaves {
		mp := &PromiseObject{}
		err := json.Unmarshal(l.LeafValue, &mp)
		if err != nil {
			panic(err)
		}
		setReq.Leaves = append(setReq.Leaves, &trillian.MapLeaf{
			Index:     mp.Key,
			LeafValue: mp.Value,
		})
		endID = l.LeafIndex
	}
	mapperMetadata.HighestFullyCompletedSeq = endID

	mapperBytes, err := proto.Marshal(mapperMetadata)
	if err != nil {
		return false, fmt.Errorf("failed to marshal mapper metadata as 'bytes': err %v", err)
	}

	setReq.Metadata = mapperBytes
	//spew.Dump(setReq)
	setResp, err := vmap.SetLeaves(context.Background(), setReq)
	if err != nil {
		return false, err
	}
	smr := setResp.GetMapRoot()
	smrbytes, err := proto.Marshal(setResp.MapRoot)
	if err != nil {
		panic(err)
	}

	//Now we need to insert this into the root log
	rootResp, err := logclient.QueueLeaf(context.Background(), &trillian.QueueLeafRequest{
		LogId: TreeID_Root,
		Leaf: &trillian.LogLeaf{
			LeafValue: smrbytes,
		},
	})
	if err != nil {
		panic(err)
	}
	for {
		llr, err := logclient.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
			LogId: TreeID_Root,
		})
		if err != nil {
			panic(err)
		}
		rootloginclusion, err := logclient.GetInclusionProofByHash(context.Background(), &trillian.GetInclusionProofByHashRequest{
			LogId:    TreeID_Root,
			LeafHash: rootResp.QueuedLeaf.Leaf.LeafIdentityHash,
			TreeSize: llr.SignedLogRoot.TreeSize,
		})
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		slrbytes, err := proto.Marshal(rootloginclusion.SignedLogRoot)
		if err != nil {
			panic(err)
		}
		slrinc, err := proto.Marshal(rootloginclusion.Proof[0])
		if err != nil {
			panic(err)
		}

		//Here we would communicate with the auditors

		var newMapRoot types.MapRootV1
		if err := newMapRoot.UnmarshalBinary(smr.MapRoot); err != nil {
			panic(err)
		}

		dbsmr := &dbSMR{
			Revision:      newMapRoot.Revision,
			LogInclusion:  slrinc,
			LogSignedRoot: slrbytes,
			LogSize:       llr.SignedLogRoot.TreeSize,
		}
		err = DB.InsertMapRoot(dbsmr)
		if err != nil {
			panic(err)
		}

		break
	}

	d := time.Since(start)
	fmt.Printf("Map run complete, took %.1f secs to update %d values (%0.2f/s)\n", d.Seconds(), len(setReq.Leaves), float64(len(setReq.Leaves))/d.Seconds())

	return true, nil
}

func primeSigRoots(certifierIDs []string) {
	resp, err := vmap.GetSignedMapRoot(context.Background(), &trillian.GetSignedMapRootRequest{
		MapId: TreeID_Map,
	})
	if err != nil {
		panic(err)
	}
	smrbytes, err := proto.Marshal(resp.MapRoot)
	if err != nil {
		panic(err)
	}
	llr, err := logclient.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
		LogId: TreeID_Root,
	})
	if err != nil {
		panic(err)
	}
	if llr.SignedLogRoot.TreeSize == 0 {
		return
	}
	leafhash, _ := rfc6962.DefaultHasher.HashLeaf(smrbytes)
	rootloginclusion, err := logclient.GetInclusionProofByHash(context.Background(), &trillian.GetInclusionProofByHashRequest{
		LogId:    TreeID_Root,
		LeafHash: leafhash,
		TreeSize: llr.SignedLogRoot.TreeSize,
	})
	if err != nil {
		panic("could not find inclusion proof for bootstrap\n")
	}

	slrbytes, err := proto.Marshal(rootloginclusion.SignedLogRoot)
	if err != nil {
		panic(err)
	}
	slrinc, err := proto.Marshal(rootloginclusion.Proof[0])
	if err != nil {
		panic(err)
	}

	var newMapRoot types.MapRootV1
	if err := newMapRoot.UnmarshalBinary(resp.MapRoot.MapRoot); err != nil {
		panic(err)
	}

	dbsmr := &dbSMR{
		Revision:      newMapRoot.Revision,
		LogInclusion:  slrinc,
		LogSignedRoot: slrbytes,
		LogSize:       llr.SignedLogRoot.TreeSize,
	}
	err = DB.InsertMapRoot(dbsmr)
	if err != nil {
		panic(err)
	}

}
func startMappingLoops(certifierIDs []string) {
	primeSigRoots(certifierIDs)
	for {
		found, err := PerformOneMap(certifierIDs)
		if err != nil {
			panic(err)
		}
		if !found {
			time.Sleep(500 * time.Millisecond)
		}
	}
}
