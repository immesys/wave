package main

import (
	"context"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/immesys/wave/storage/vldmstorage3/vldmpb"
)

type api struct {
	logId  int64
	mapId  int64
	client trillian.TrillianLogClient
}

func (a *api) GetLogItem(ctx context.Context, p *vldmpb.GetLogItemParams) (*vldmpb.GetLogItemResponse, error) {
	resp, err := a.client.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
		LogId:     a.logId,
		LeafIndex: p.Index,
		TreeSize:  p.Size,
	})
	if err != nil {
		return nil, err
	}
	ba, err := proto.Marshal(resp)
	if err != nil {
		panic(err)
	}
	return &vldmpb.GetLogItemResponse{TrillianGetEntryAndProofResponse: ba}, nil
}

func (a *api) GetLogConsistency(ctx context.Context, p *vldmpb.GetConsistencyParams) (*vldmpb.GetConsistencyResponse, error) {
	resp, err := logclient.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          a.logId,
		FirstTreeSize:  p.From,
		SecondTreeSize: p.To,
	})
	if err != nil {
		return nil, err
	}
	ba, err := proto.Marshal(resp.Proof)
	if err != nil {
		panic(err)
	}
	return &vldmpb.GetConsistencyResponse{TrillianProof: ba}, nil
}

// func logSTH(logid int64, w http.ResponseWriter, r *http.Request) {
// 	resp, err := logclient.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
// 		LogId: logid,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	ba, err := proto.Marshal(resp.SignedLogRoot)
// 	if err != nil {
// 		panic(err)
// 	}
// 	w.WriteHeader(200)
// 	w.Write(ba)
// }
