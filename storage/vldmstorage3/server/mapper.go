package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	"github.com/immesys/wave/storage/vldmstorage2/pb"
)

const LogBatchSize = 280

var mapperLogClient *client.LogClient

func PerformOneMap() (bool, error) {
	start := time.Now()
	fmt.Printf("starting map run\n")
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
	fmt.Printf("Fetching entries [%d+] from log\n", startEntry)

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
			LeafValue: smr.MapRoot,
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
			fmt.Printf("got error: %v", err)
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
		{
			ts, sigR, sigS, err := SignMapRoot("mock", smrbytes)
			//error should not happen because we chose the identity
			if err != nil {
				panic(err)
			}
			var newMapRoot types.MapRootV1
			if err := newMapRoot.UnmarshalBinary(smr.MapRoot); err != nil {
				panic(err)
			}

			dbsmr := &dbSMR{
				Revision:      newMapRoot.Revision,
				SigIdentity:   "mock",
				Timestamp:     ts,
				R:             sigR,
				S:             sigS,
				LogInclusion:  slrinc,
				LogSignedRoot: slrbytes,
				LogSize:       llr.SignedLogRoot.TreeSize,
			}
			err = DB.InsertSignedMapRoot(dbsmr)
			if err != nil {
				panic(err)
			}
		}
		break
	}

	d := time.Since(start)
	fmt.Printf("Map run complete, took %.1f secs to update %d values (%0.2f/s)\n", d.Seconds(), len(setReq.Leaves), float64(len(setReq.Leaves))/d.Seconds())

	return true, nil
}

func startMappingLoops() {
	for {
		found, err := PerformOneMap()
		if err != nil {
			panic(err)
		}
		if !found {
			time.Sleep(500 * time.Millisecond)
		}
	}
}
