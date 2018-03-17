package eapi

import (
	"context"
	"net"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/wve"
	"google.golang.org/grpc"
)

type eAPI struct {
	engines map[[32]byte]*engine.Engine
	s       *grpc.Server
	state   iapi.WaveState
}

func NewEAPI(state iapi.WaveState) *eAPI {
	api := &eAPI{
		engines: make(map[[32]byte]*engine.Engine),
		state:   state,
	}
	return api
}
func (e *eAPI) StartServer(listenaddr string) {
	grpcServer := grpc.NewServer()
	e.s = grpcServer
	l, err := net.Listen("tcp", listenaddr)
	if err != nil {
		panic(err)
	}
	pb.RegisterWAVEServer(grpcServer, e)
	go grpcServer.Serve(l)
}
func (e *eAPI) getEngine(ctx context.Context, in *pb.Perspective) *engine.Engine {
	secret := ConvertEntitySecret(ctx, in.EntitySecret)
	if secret == nil {
		panic("nil secret")
	}
	loc := LocationSchemeInstance(in.Location)
	id := secret.Entity.ArrayKeccak256()
	eng, ok := e.engines[id]
	if !ok {
		var err error
		eng, err = engine.NewEngine(context.Background(), e.state, iapi.SI(), secret, loc)
		if err != nil {
			panic(err)
		}
		e.engines[id] = eng
	}
	return eng
}
func (e *eAPI) CreateEntity(ctx context.Context, p *pb.CreateEntityParams) (*pb.CreateEntityResponse, error) {
	params := &iapi.PNewEntity{
		ValidFrom:                    TimeFromInt64MillisWithDefault(p.ValidFrom, time.Now()),
		ValidUntil:                   TimeFromInt64MillisWithDefault(p.ValidUntil, time.Now().Add(30*24*time.Hour)),
		CommitmentRevocationLocation: LocationSchemeInstance(p.RevocationLocation),
	}
	if params.CommitmentRevocationLocation != nil && !params.CommitmentRevocationLocation.Supported() {
		panic("unsupported location")
		//actually the IAPI functions should test the parameters better
	}
	resp, err := iapi.NewEntity(ctx, params)
	if err != nil {
		panic(err)
	}
	return &pb.CreateEntityResponse{
		PublicDER: resp.PublicDER,
		SecretDER: resp.SecretDER,
	}, nil
}
func (e *eAPI) CreateAttestation(ctx context.Context, p *pb.CreateAttestationParams) (*pb.CreateAttestationResponse, error) {
	eng := e.getEngine(ctx, p.Perspective)
	if eng == nil {
		panic("wtf")
	}
	subHash := iapi.HashSchemeInstanceFromMultihash(p.SubjectHash)
	subLoc := LocationSchemeInstance(p.SubjectLocation)
	ent, val, err := eng.LookupEntity(ctx, subHash, subLoc)
	if !val.Valid {
		panic("Subject not valid")
	}
	if ent == nil {
		panic("subject nil")
	}
	secret := ConvertEntitySecret(ctx, p.Perspective.EntitySecret)
	loc := LocationSchemeInstance(p.Perspective.Location)
	hashScheme, err := iapi.SI().HashSchemeFor(loc)
	if err != nil {
		panic(err)
	}
	params := &iapi.PCreateAttestation{
		Policy:           ConvertPolicy(p.Policy),
		HashScheme:       hashScheme,
		BodyScheme:       ConvertBodyScheme(p.BodyScheme),
		Attester:         secret,
		AttesterLocation: loc,
		Subject:          ent,
		SubjectLocation:  subLoc,
		ValidFrom:        TimeFromInt64MillisWithDefault(p.ValidFrom, time.Now()),
		ValidUntil:       TimeFromInt64MillisWithDefault(p.ValidUntil, time.Now().Add(30*24*time.Hour)),
	}
	resp, err := iapi.CreateAttestation(ctx, params)
	return &pb.CreateAttestationResponse{
		DER: resp.DER,
	}, nil
}
func (e *eAPI) PublishEntity(ctx context.Context, p *pb.PublishEntityParams) (*pb.PublishEntityResponse, error) {
	loc := LocationSchemeInstance(p.Location)
	rve, err := iapi.ParseEntity(ctx, &iapi.PParseEntity{
		DER: p.DER,
	})
	if err != nil {
		return &pb.PublishEntityResponse{
			Error: ToError(err),
		}, nil
	}
	hi, uerr := iapi.SI().PutEntity(ctx, loc, rve.Entity)
	if uerr != nil {
		return &pb.PublishEntityResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not put entity", uerr)),
		}, nil
	}
	return &pb.PublishEntityResponse{
		Hash: hi.Multihash(),
	}, nil
}
func (e *eAPI) PublishAttestation(ctx context.Context, p *pb.PublishAttestationParams) (*pb.PublishAttestationResponse, error) {
	loc := LocationSchemeInstance(p.Location)
	rvp, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
		DER: p.DER,
	})

	if err != nil {
		return &pb.PublishAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	if rvp.IsMalformed {
		return &pb.PublishAttestationResponse{
			Error: ToError(wve.Err(wve.InternalError, "attestation is malformed")),
		}, nil
	}
	hi, uerr := iapi.SI().PutAttestation(ctx, loc, rvp.Attestation)
	if uerr != nil {
		return &pb.PublishAttestationResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not put attestation", uerr)),
		}, nil
	}
	subjHI, subjLoc := rvp.Attestation.Subject()
	uerr = iapi.SI().Enqueue(ctx, subjLoc, subjHI, hi)
	if uerr != nil {
		return &pb.PublishAttestationResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not enqueue attestation", uerr)),
		}, nil
	}
	return &pb.PublishAttestationResponse{
		Hash: hi.Multihash(),
	}, nil
}
func (e *eAPI) AddAttestation(ctx context.Context, p *pb.AddAttestationParams) (*pb.AddAttestationResponse, error) {
	//TODO even if a dot is inserted with a prover key, it seems we insert it as pending and don't actually
	//treat it as decrypted unless we also somehow decrypt it from scratch.
	eng := e.getEngine(ctx, p.Perspective)
	dctx := engine.NewEngineDecryptionContext(eng)
	if p.ProverKey != nil {
		dctx.SetProverKey(p.ProverKey)
	}
	//Don't use verifier key when adding attestation
	rvp, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
		DER:               p.DER,
		DecryptionContext: dctx,
	})
	if err != nil {
		return &pb.AddAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	if rvp.IsMalformed {
		return &pb.AddAttestationResponse{
			Error: ToError(wve.Err(wve.MalformedObject, "attestation malformed")),
		}, nil
	}
	uerr := eng.InsertAttestation(ctx, rvp.Attestation)
	if uerr != nil {
		return &pb.AddAttestationResponse{
			Error: ToError(wve.ErrW(wve.UnknownError, "could not insert", uerr)),
		}, nil
	}
	return &pb.AddAttestationResponse{}, nil
}
func (e *eAPI) LookupAttestations(ctx context.Context, p *pb.LookupAttestationsParams) (*pb.LookupAttestationsResponse, error) {
	if len(p.ToEntity) != 0 && len(p.FromEntity) != 0 {
		return &pb.LookupAttestationsResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "you should specify To entity or From entity, not both")),
		}, nil
	}
	eng := e.getEngine(ctx, p.Perspective)
	var chlr chan *engine.LookupResult
	var cherr chan error
	filter := &iapi.LookupFromFilter{}
	if len(p.FromEntity) != 0 {
		hi := iapi.HashSchemeInstanceFromMultihash(p.FromEntity)
		if !hi.Supported() {
			return &pb.LookupAttestationsResponse{
				Error: ToError(wve.Err(wve.InvalidMultihash, "FromEntity is not a supported multihash")),
			}, nil
		}
		chlr, cherr = eng.LookupAttestationsFrom(ctx, hi, filter)
	} else if len(p.ToEntity) != 0 {
		hi := iapi.HashSchemeInstanceFromMultihash(p.ToEntity)
		if !hi.Supported() {
			return &pb.LookupAttestationsResponse{
				Error: ToError(wve.Err(wve.InvalidMultihash, "FromEntity is not a supported multihash")),
			}, nil
		}
		chlr, cherr = eng.LookupAttestationsTo(ctx, hi, filter)
	}
	rv := &pb.LookupAttestationsResponse{}
	rva := []*pb.Attestation{}
results:
	for {
		select {
		case lr, ok := <-chlr:
			if !ok {
				//We are done consuming results
				break results
			}
			rva = append(rva, ConvertLookupResult(lr))
		case err := <-cherr:
			return &pb.LookupAttestationsResponse{
				Error: ToError(wve.ErrW(wve.LookupFailure, "could not complete lookup", err)),
			}, nil
		}
	}
	rv.Results = rva
	return rv, nil
}
func (e *eAPI) ResyncPerspectiveGraph(ctx context.Context, p *pb.ResyncPerspectiveGraphParams) (*pb.ResyncPerspectiveGraphResponse, error) {
	eng := e.getEngine(ctx, p.Perspective)
	err := eng.ResyncEntireGraph(ctx)
	if err != nil {
		panic(err)
	}
	return &pb.ResyncPerspectiveGraphResponse{}, nil
}
func (e *eAPI) SyncStatus(ctx context.Context, p *pb.SyncParams) (*pb.SyncResponse, error) {
	eng := e.getEngine(ctx, p.Perspective)
	ss, err := eng.SyncStatus(ctx)
	if err != nil {
		panic(err)
	}
	rv := &pb.SyncResponse{
		TotalSyncRequests: ss.TotalSyncRequests,
		CompletedSyncs:    ss.TotalCompletedSyncs,
	}
	rv.StorageStatus = make(map[string]*pb.StorageDriverStatus)
	for drv, drvs := range ss.StorageStatus {
		sds := &pb.StorageDriverStatus{
			Operational: drvs.Operational,
			Info:        make(map[string]string),
		}
		for k, v := range drvs.Info {
			sds.Info[k] = v
		}
		rv.StorageStatus[drv] = sds
	}
	return rv, nil
}
func (e *eAPI) WaitForSyncComplete(p *pb.SyncParams, srv pb.WAVE_WaitForSyncCompleteServer) error {
	ctx := srv.Context()
	eng := e.getEngine(ctx, p.Perspective)
	ss, err := eng.SyncStatus(ctx)
	if err != nil {
		panic(err)
	}
	emit := func(ss *engine.SyncStatus) {
		rv := &pb.SyncResponse{
			TotalSyncRequests: ss.TotalSyncRequests,
			CompletedSyncs:    ss.TotalCompletedSyncs,
		}
		rv.StorageStatus = make(map[string]*pb.StorageDriverStatus)
		for drv, drvs := range ss.StorageStatus {
			sds := &pb.StorageDriverStatus{
				Operational: drvs.Operational,
				Info:        make(map[string]string),
			}
			for k, v := range drvs.Info {
				sds.Info[k] = v
			}
			rv.StorageStatus[drv] = sds
		}
		srv.Send(rv)
	}
	emit(ss)
	waitchan := eng.WaitForEmptySyncQueue()
	for {
		if srv.Context().Err() != nil {
			return srv.Context().Err()
		}
		select {
		case <-waitchan:
			ss, err := eng.SyncStatus(ctx)
			if err != nil {
				panic(err)
			}
			emit(ss)
			return nil
		case <-time.After(500 * time.Millisecond):
			ss, err := eng.SyncStatus(ctx)
			if err != nil {
				panic(err)
			}
			emit(ss)
		}
	}
	return nil
}
