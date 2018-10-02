package main

import (
	"context"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/trillian"
	"github.com/immesys/wave/storage/vldmstorage3/vldmpb"
)

type api struct {
	submu sync.Mutex
	subs  []*mrsubscription
}
type mrsubscription struct {
	Ch  chan *trillian.SignedMapRoot
	Ctx context.Context
}

var API *api

func init() {
	API = &api{}
}

func (a *api) SubmitMapRoot(mr *trillian.SignedMapRoot) {
	newsubs := []*mrsubscription{}
	a.submu.Lock()
	for _, sub := range a.subs {
		if sub.Ctx.Err() != nil {
			continue
		}
		sub.Ch <- mr
		newsubs = append(newsubs, sub)
	}
	a.subs = newsubs
	a.submu.Unlock()
}

func (a *api) SubscribeMapHeads(p *vldmpb.SubscribeParams, r vldmpb.VLDM_SubscribeMapHeadsServer) error {
	ch := make(chan *trillian.SignedMapRoot, 100)
	a.submu.Lock()
	a.subs = append(a.subs, &mrsubscription{
		Ch:  ch,
		Ctx: r.Context(),
	})
	a.submu.Unlock()
	for {
		select {
		case mh := <-ch:
			ba, err := proto.Marshal(mh)
			if err != nil {
				panic(err)
			}
			err = r.Send(&vldmpb.MapHead{
				TrillianSignedMapRoot: ba,
			})
			if err != nil {
				return err
			}
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
}
func (a *api) GetLogHead(ctx context.Context, p *vldmpb.GetLogHeadParams) (*vldmpb.GetLogHeadResponse, error) {
	logId = TreeID_Root
	if p.IsOperation {
		logId = TreeID_Op
	}
	resp, err := logclient.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: logId,
	})
	if err != nil {
		return nil, err
	}
	ba, err := proto.Marshal(resp.SignedLogRoot)
	if err != nil {
		panic(err)
	}
	return &vldmpb.GetLogHeadResponse{TrillianSignedLogRoot: ba}, nil
}
func (a *api) GetLogItem(ctx context.Context, p *vldmpb.GetLogItemParams) (*vldmpb.GetLogItemResponse, error) {
	logId = TreeID_Root
	if p.IsOperation {
		logId = TreeID_Op
	}
	resp, err := logclient.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
		LogId:     logId,
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
	logId = TreeID_Root
	if p.IsOperation {
		logId = TreeID_Op
	}
	resp, err := logclient.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          logId,
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

func (a *api) SubmitSignedMapHead(ctx context.Context, p *vldmpb.SubmitParams) (*vldmpb.SubmitResponse, error) {
	//TODO
	return nil, nil
}
