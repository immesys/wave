package eapi

import (
	"context"
	"net"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
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
	loc := LocationSchemeInstance(in.Location)
	id := secret.Entity.ArrayKeccak256()
	eng, ok := e.engines[id]
	if !ok {
		eng, err := engine.NewEngine(context.Background(), e.state, iapi.SI(), secret, loc)
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
	//eng := e.getEngine(ctx, p.Perspective)
	subHash := ConvertHashSchemeInstance(p.Subject)
	subLoc := LocationSchemeInstance(p.SubjectLocation)
	ent, err := e.state.GetEntityByHashSchemeInstanceG(ctx, subHash)
	if err != nil {
		panic(err)
	}
	if ent == nil {
		ent, err = iapi.SI().GetEntity(ctx, subLoc, subHash)
		if err != nil {
			panic(err)
		}
	}
	secret := ConvertEntitySecret(ctx, p.Perspective.EntitySecret)
	loc := LocationSchemeInstance(p.Perspective.Location)
	params := &iapi.PCreateAttestation{
		Policy:           ConvertPolicy(p.Policy),
		HashScheme:       ConvertHashScheme(p.AttesterHashScheme),
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
		panic(err)
	}
	hi, err := iapi.SI().PutEntity(ctx, loc, rve.Entity)
	if err != nil {
		panic(err)
	}
	pbhash := ToPbHash(hi)
	return &pb.PublishEntityResponse{
		Hash: pbhash,
	}, nil
}
func (e *eAPI) PublishAttestation(ctx context.Context, p *pb.PublishAttestationParams) (*pb.PublishAttestationResponse, error) {
	loc := LocationSchemeInstance(p.Location)
	rve, err := iapi.ParseEntity(ctx, &iapi.PParseEntity{
		DER: p.DER,
	})
	if err != nil {
		panic(err)
	}
	hi, err := iapi.SI().PutEntity(ctx, loc, rve.Entity)
	if err != nil {
		panic(err)
	}
	pbhash := ToPbHash(hi)
	return &pb.PublishAttestationResponse{
		Hash: pbhash,
	}, nil
}
func (e *eAPI) AddAttestation(ctx context.Context, p *pb.AddAttestationParams) (*pb.AddAttestationResponse, error) {
	panic("ni")
}
func (e *eAPI) LookupAttestations(ctx context.Context, p *pb.LookupAttestationsParams) (*pb.LookupAttestationsResponse, error) {
	panic("ni")
}
