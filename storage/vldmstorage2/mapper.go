package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	pb "github.com/immesys/wave/storage/vldmstorage3/vldmpb"
)

const LogBatchSize = 280

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
	smrbytes, err := proto.Marshal(setResp.MapRoot)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("smrbytes: %x\n", smrbytes)
	ctx := context.Background()
	llf := &trillian.LogLeaf{
		LeafValue: smrbytes,
	}
	_, err = logclient.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: TreeID_Root,
		Leaf:  llf,
	})
	if err != nil {
		panic(err)
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
