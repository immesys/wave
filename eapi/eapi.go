package eapi

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/policyutils/rtree"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"google.golang.org/grpc"
)

type EAPI struct {
	engines  map[[32]byte]*engine.Engine
	npengine *engine.Engine
	s        *grpc.Server
	state    iapi.WaveState
}

func NewEAPI(state iapi.WaveState) *EAPI {
	api := &EAPI{
		engines: make(map[[32]byte]*engine.Engine),
		state:   state,
	}
	npengine, err := engine.NewEngineWithNoPerspective(context.Background(), state, iapi.SI())
	if err != nil {
		panic(err)
	}
	api.npengine = npengine
	return api
}
func (e *EAPI) StartServer(listenaddr string, httplistenaddr string) {
	grpcServer := grpc.NewServer()
	e.s = grpcServer
	l, err := net.Listen("tcp", listenaddr)
	if err != nil {
		panic(err)
	}
	pb.RegisterWAVEServer(grpcServer, e)
	go grpcServer.Serve(l)
	go runHTTPserver(listenaddr, httplistenaddr)
}
func (e *EAPI) getEngine(ctx context.Context, in *pb.Perspective) (*engine.Engine, wve.WVE) {
	if in == nil {
		return nil, wve.Err(wve.InvalidParameter, "missing perspective parameter")
	}
	secret, err := ConvertEntitySecret(ctx, in.EntitySecret)
	if err != nil {
		return nil, err
	}
	loc, err := LocationSchemeInstance(in.Location)
	if err != nil {
		return nil, err
	}
	if loc == nil {
		loc = iapi.SI().DefaultLocation(ctx)
	}
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
	val, uerr := eng.CheckEntity(ctx, eng.Perspective().Entity)
	if uerr != nil {
		return nil, wve.ErrW(wve.InternalError, "could not check perspective entity", uerr)
	}
	if !val.Valid {
		return nil, wve.Err(wve.InvalidParameter, fmt.Sprintf("perspective entity is invalid: %s", val.Message))
	}
	return eng, nil
}
func (e *EAPI) getEngineNoPerspective() *engine.Engine {
	return e.npengine
}
func (e *EAPI) Inspect(ctx context.Context, p *pb.InspectParams) (*pb.InspectResponse, error) {
	eng := e.getEngineNoPerspective()
	//Try as entitysecret

	//Bit of a hack: users might accidentally send us PEM instead of DER. Check that first:
	der := p.Content
	pblock, _ := pem.Decode(p.Content)
	if pblock != nil {
		der = pblock.Bytes
	}

	es, err := iapi.ParseEntitySecrets(ctx, &iapi.PParseEntitySecrets{
		DER: der,
	})
	if es != nil {
		validity, err := eng.CheckEntity(ctx, es.Entity)
		if err != nil {
			return &pb.InspectResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not check entity", err)),
			}, nil
		}
		return &pb.InspectResponse{
			Entity: ConvertEntityWVal(es.Entity, validity),
		}, nil
	}
	//Try as attestation
	kpdctx := iapi.NewKeyPoolDecryptionContext()
	if p.ProverKey != nil {
		kpdctx.SetWR1ProverBodyKey(p.ProverKey)
	}
	if p.VerifierKey != nil {
		kpdctx.SetWR1VerifierBodyKey(p.VerifierKey)
	}
	att, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
		DER:               der,
		DecryptionContext: kpdctx,
	})
	if err != nil || att.IsMalformed {
		return &pb.InspectResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "could not decode contents")),
		}, nil
	}
	pba := ConvertProofAttestation(att.Attestation)
	validity, uerr := eng.CheckAttestation(ctx, att.Attestation)
	if uerr != nil {
		return &pb.InspectResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "could not check attestation")),
		}, nil
	}
	pba.Validity = &pb.AttestationValidity{
		Valid:        validity.Valid,
		Revoked:      validity.Revoked,
		Expired:      validity.Expired,
		Malformed:    validity.Malformed,
		NotDecrypted: validity.NotDecrypted,
		SrcInvalid:   validity.SrcInvalid,
		DstInvalid:   validity.DstInvalid,
		Message:      validity.Message,
	}
	return &pb.InspectResponse{
		Attestation: pba,
	}, nil
}
func (e *EAPI) ListLocations(ctx context.Context, p *pb.ListLocationsParams) (*pb.ListLocationsResponse, error) {
	locs, err := iapi.SI().RegisteredLocations(ctx)
	if err != nil {
		return &pb.ListLocationsResponse{
			Error: ToError(wve.ErrW(wve.InternalError, "could not obtain location list", err)),
		}, nil
	}
	pblocs := make(map[string]*pb.Location)
	for name, loc := range locs {
		pblocs[name] = ToPbLocation(loc)
	}
	return &pb.ListLocationsResponse{
		AgentLocations: pblocs,
	}, nil
}
func (e *EAPI) CreateEntity(ctx context.Context, p *pb.CreateEntityParams) (*pb.CreateEntityResponse, error) {
	revloc, err := LocationSchemeInstance(p.RevocationLocation)
	if err != nil {
		return &pb.CreateEntityResponse{
			Error: ToError(err),
		}, nil
	}
	if revloc == nil {
		revloc = iapi.SI().DefaultLocation(ctx)
	}
	params := &iapi.PNewEntity{
		ValidFrom:                    TimeFromInt64MillisWithDefault(p.ValidFrom, time.Now()),
		ValidUntil:                   TimeFromInt64MillisWithDefault(p.ValidUntil, time.Now().Add(30*24*time.Hour)),
		CommitmentRevocationLocation: revloc,
	}
	//spew.Dump(params)
	if p.SecretPassphrase != "" {
		params.Passphrase = iapi.String(p.SecretPassphrase)
	}
	if params.CommitmentRevocationLocation != nil && !params.CommitmentRevocationLocation.Supported() {
		panic("unsupported location")
		//actually the IAPI functions should test the parameters better
	}
	resp, err := iapi.NewEntity(ctx, params)
	if err != nil {
		panic(err)
	}
	hi := iapi.KECCAK256.Instance(resp.PublicDER)
	return &pb.CreateEntityResponse{
		PublicDER: resp.PublicDER,
		SecretDER: resp.SecretDER,
		Hash:      hi.Multihash(),
	}, nil
}
func (e *EAPI) CreateAttestation(ctx context.Context, p *pb.CreateAttestationParams) (*pb.CreateAttestationResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	subHash := iapi.HashSchemeInstanceFromMultihash(p.SubjectHash)
	subLoc, err := LocationSchemeInstance(p.SubjectLocation)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	if subLoc == nil {
		subLoc = iapi.SI().DefaultLocation(ctx)
	}
	ent, val, uerr := eng.LookupEntity(ctx, subHash, subLoc)
	if uerr != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.LookupFailure, "could not resolve subject", uerr)),
		}, nil
	}
	if !val.Valid {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.Err(wve.MissingParameter, "subject is not valid")),
		}, nil
	}
	if ent == nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.Err(wve.MissingParameter, "subject is nil")),
		}, nil
	}
	hashScheme, uerr := iapi.SI().HashSchemeFor(eng.PerspectiveLocation())
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.UnsupportedHashScheme, "could not get hash scheme for location", err)),
		}, nil
	}
	dctx := engine.NewEngineDecryptionContext(eng)
	dctx.AutoLoadPartitionSecrets(true)
	pol, err := e.ConvertPolicy(p.Policy)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	params := &iapi.PCreateAttestation{
		Policy:            pol,
		EncryptionContext: dctx,
		HashScheme:        hashScheme,
		BodyScheme:        ConvertBodyScheme(p.BodyScheme),
		Attester:          eng.Perspective(),
		AttesterLocation:  eng.PerspectiveLocation(),
		Subject:           ent,
		SubjectLocation:   subLoc,
		ValidFrom:         TimeFromInt64MillisWithDefault(p.ValidFrom, time.Now()),
		ValidUntil:        TimeFromInt64MillisWithDefault(p.ValidUntil, time.Now().Add(30*24*time.Hour)),
	}
	if params.BodyScheme == nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "invalid body scheme")),
		}, nil
	}
	resp, err := iapi.CreateAttestation(ctx, params)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	hi := iapi.KECCAK256.Instance(resp.DER)

	if p.Publish {
		rvp, err := iapi.ParseAttestation(ctx, &iapi.PParseAttestation{
			DER: resp.DER,
		})
		if err != nil {
			return &pb.CreateAttestationResponse{
				Error: ToError(err),
			}, nil
		}
		if rvp.IsMalformed {
			return &pb.CreateAttestationResponse{
				Error: ToError(wve.Err(wve.InternalError, "attestation is malformed")),
			}, nil
		}
		hi, uerr := iapi.SI().PutAttestation(ctx, subLoc, rvp.Attestation)
		if uerr != nil {
			return &pb.CreateAttestationResponse{
				Error: ToError(wve.ErrW(wve.StorageError, "could not put attestation", uerr)),
			}, nil
		}

		uerr = iapi.SI().Enqueue(ctx, subLoc, ent.Keccak256HI(), hi)
		if uerr != nil {
			return &pb.CreateAttestationResponse{
				Error: ToError(wve.ErrW(wve.StorageError, "could not enqueue attestation", uerr)),
			}, nil
		}
	}
	return &pb.CreateAttestationResponse{
		DER:         resp.DER,
		VerifierKey: resp.VerifierKey,
		ProverKey:   resp.ProverKey,
		Hash:        hi.Multihash(),
	}, nil
}
func (e *EAPI) PublishEntity(ctx context.Context, p *pb.PublishEntityParams) (*pb.PublishEntityResponse, error) {
	loc, err := LocationSchemeInstance(p.Location)
	if err != nil {
		return &pb.PublishEntityResponse{
			Error: ToError(err),
		}, nil
	}
	if loc == nil {
		loc = iapi.SI().DefaultLocation(ctx)
	}
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
func (e *EAPI) PublishAttestation(ctx context.Context, p *pb.PublishAttestationParams) (*pb.PublishAttestationResponse, error) {
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
	subjHI, subjLoc := rvp.Attestation.Subject()
	hi, uerr := iapi.SI().PutAttestation(ctx, subjLoc, rvp.Attestation)
	if uerr != nil {
		return &pb.PublishAttestationResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not put attestation", uerr)),
		}, nil
	}

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
func (e *EAPI) AddAttestation(ctx context.Context, p *pb.AddAttestationParams) (*pb.AddAttestationResponse, error) {
	//TODO even if a dot is inserted with a prover key, it seems we insert it as pending and don't actually
	//treat it as decrypted unless we also somehow decrypt it from scratch.
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.AddAttestationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
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
func (e *EAPI) LookupAttestations(ctx context.Context, p *pb.LookupAttestationsParams) (*pb.LookupAttestationsResponse, error) {
	if len(p.ToEntity) != 0 && len(p.FromEntity) != 0 {
		return &pb.LookupAttestationsResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "you should specify To entity or From entity, not both")),
		}, nil
	}
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.LookupAttestationsResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
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
		case err, ok := <-cherr:
			if ok {
				return &pb.LookupAttestationsResponse{
					Error: ToError(wve.ErrW(wve.LookupFailure, "could not complete lookup", err)),
				}, nil
			}
		}
	}
	rv.Results = rva
	return rv, nil
}
func (e *EAPI) ResyncPerspectiveGraph(ctx context.Context, p *pb.ResyncPerspectiveGraphParams) (*pb.ResyncPerspectiveGraphResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.ResyncPerspectiveGraphResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	uerr := eng.ResyncEntireGraph(ctx)
	if uerr != nil {
		return &pb.ResyncPerspectiveGraphResponse{
			Error: ToError(wve.ErrW(wve.UnknownError, "could not sync graph", uerr)),
		}, nil
	}
	return &pb.ResyncPerspectiveGraphResponse{}, nil
}
func (e *EAPI) SyncStatus(ctx context.Context, p *pb.SyncParams) (*pb.SyncResponse, error) {
	eng, werr := e.getEngine(ctx, p.Perspective)
	if werr != nil {
		return &pb.SyncResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", werr)),
		}, nil
	}
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
func (e *EAPI) WaitForSyncCompleteHack(p *pb.SyncParams) error {
	ctx := context.Background()
	eng, werr := e.getEngine(ctx, p.Perspective)
	if werr != nil {
		return werr
	}
	waitchan := eng.WaitForEmptySyncQueue()
	<-waitchan
	return nil
}

func (e *EAPI) WaitForSyncComplete(p *pb.SyncParams, srv pb.WAVE_WaitForSyncCompleteServer) error {
	ctx := srv.Context()
	eng, werr := e.getEngine(ctx, p.Perspective)
	if werr != nil {
		srv.Send(&pb.SyncResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", werr)),
		})
		return nil
	}
	ss, err := eng.SyncStatus(ctx)
	if err != nil {
		srv.Send(&pb.SyncResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", werr)),
		})
		return nil
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
				srv.Send(&pb.SyncResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "sync error", err)),
				})
				return nil
			}
			emit(ss)
			return nil
		case <-time.After(500 * time.Millisecond):
			ss, err := eng.SyncStatus(ctx)
			if err != nil {
				srv.Send(&pb.SyncResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "sync error", err)),
				})
				return nil
			}
			emit(ss)
		}
	}
	return nil
}

func (e *EAPI) VerifyProof(ctx context.Context, p *pb.VerifyProofParams) (*pb.VerifyProofResponse, error) {
	eng := e.getEngineNoPerspective()
	dctx := engine.NewEngineDecryptionContext(eng)
	resp, werr := iapi.VerifyRTreeProof(ctx, &iapi.PVerifyRTreeProof{
		DER:  p.ProofDER,
		VCtx: dctx,
	})
	if werr != nil {
		return &pb.VerifyProofResponse{
			Error: ToError(werr),
		}, nil
	}
	proof := pb.Proof{
		Elements:        make([]*pb.Attestation, len(resp.Attestations)),
		Paths:           make([]*pb.ProofPath, len(resp.Paths)),
		Policy:          ToPbPolicy(resp.Policy),
		Expiry:          resp.Expires.UnixNano() / 1e6,
		Subject:         resp.Subject.Multihash(),
		SubjectLocation: ToPbLocation(resp.SubjectLocation),
	}

	for idx, att := range resp.Attestations {
		//Double check the attestation
		val, err := eng.CheckAttestation(ctx, att)
		if err != nil {
			return &pb.VerifyProofResponse{
				Error: ToError(wve.ErrW(wve.InternalError, "could not check attestation", err)),
			}, nil
		}
		if !val.Valid {
			return &pb.VerifyProofResponse{
				Error: ToError(wve.Err(wve.ProofInvalid, "proof contains expired or revoked attestations")),
			}, nil
		}
		proof.Elements[idx] = ConvertProofAttestation(att)
	}

	for idx, path := range resp.Paths {
		prp := &pb.ProofPath{}
		for _, p := range path {
			prp.Elements = append(prp.Elements, int32(p))
		}
		proof.Paths[idx] = prp
	}
	return &pb.VerifyProofResponse{
		Result: &proof,
	}, nil
}
func (e *EAPI) ResolveHash(ctx context.Context, p *pb.ResolveHashParams) (*pb.ResolveHashResponse, error) {
	var en *engine.Engine
	if p.Perspective == nil {
		en = e.getEngineNoPerspective()
	} else {
		var err wve.WVE
		en, err = e.getEngine(ctx, p.Perspective)
		if err != nil {
			return &pb.ResolveHashResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
			}, nil
		}
	}
	hi := iapi.HashSchemeInstanceFromMultihash(p.Hash)
	if !hi.Supported() {
		return &pb.ResolveHashResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "invalid hash")),
		}, nil
	}
	//Try resolve it as an entity first
	locs, err := iapi.SI().RegisteredLocations(ctx)
	if err != nil {
		panic(err)
	}
	for lname, loc := range locs {
		pbloc := ToPbLocation(loc)
		pbloc.AgentLocation = lname
		entity, validity, err := en.LookupEntity(ctx, hi, loc)
		if err != nil {
			werr, ok := err.(wve.WVE)
			if ok && werr.Code() == 905 {
				//This is just not an entity
				goto tryatt
			}
			if err != iapi.ErrObjectNotFound {
				return &pb.ResolveHashResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "lookup failed", err)),
				}, nil
			}
		}
		if entity != nil {
			return &pb.ResolveHashResponse{
				Location: pbloc,
				Entity:   ConvertEntityWVal(entity, validity),
			}, nil
		}
	tryatt:
		//next try as attestation
		var attest *iapi.Attestation
		if p.Perspective == nil {
			attest, validity, err = en.LookupAttestationNoPerspective(ctx, hi, nil, loc)
		} else {
			attest, validity, err = en.LookupAttestationInPerspective(ctx, hi, loc)
		}
		if attest != nil {
			pba := ConvertProofAttestation(attest)
			pba.Validity = &pb.AttestationValidity{
				Valid:        validity.Valid,
				Revoked:      validity.Revoked,
				Expired:      validity.Expired,
				Malformed:    validity.Malformed,
				NotDecrypted: validity.NotDecrypted,
				SrcInvalid:   validity.SrcInvalid,
				DstInvalid:   validity.DstInvalid,
				Message:      validity.Message,
			}
			return &pb.ResolveHashResponse{
				Location:    pbloc,
				Attestation: pba,
			}, nil
		}
	}
	return &pb.ResolveHashResponse{
		Error: ToError(wve.Err(wve.LookupFailure, "no objects found")),
	}, nil
}
func (e *EAPI) BuildRTreeProof(ctx context.Context, p *pb.BuildRTreeProofParams) (*pb.BuildRTreeProofResponse, error) {
	eng, werr := e.getEngine(ctx, p.Perspective)
	if werr != nil {
		return &pb.BuildRTreeProofResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", werr)),
		}, nil
	}
	if len(p.SubjectHash) == 0 {
		p.SubjectHash = eng.Perspective().Entity.Keccak256HI().Multihash()
	}
	spol := serdes.RTreePolicy{}
	ehash := iapi.HashSchemeInstanceFromMultihash(p.Namespace)
	if !ehash.Supported() {
		return &pb.BuildRTreeProofResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "bad namespace", werr)),
		}, nil
	}
	ext := ehash.CanonicalForm()
	spol.Namespace = *ext
	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	spol.NamespaceLocation = *nsloc
	for _, st := range p.Statements {
		pset := iapi.HashSchemeInstanceFromMultihash(st.PermissionSet)
		if !pset.Supported() {
			return &pb.BuildRTreeProofResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "bad permissionset", werr)),
			}, nil
		}
		ext := pset.CanonicalForm()
		spol.Statements = append(spol.Statements, serdes.RTreeStatement{
			Permissions:   st.Permissions,
			PermissionSet: *ext,
			Resource:      st.Resource,
		})
	}
	pol, err := iapi.NewRTreePolicyScheme(spol, nil)
	if err != nil {
		panic(err)
	}
	tb, err := rtree.NewRTreeBuilder(ctx, &rtree.Params{
		Subject:      iapi.HashSchemeInstanceFromMultihash(p.SubjectHash),
		Engine:       eng,
		Policy:       pol,
		Start:        pol.WR1DomainEntity(),
		EnableOutput: true,
	})
	if err != nil {
		panic(err)
	}
	msgs := make(chan string, 1000)
	go func() {
		for {
			select {
			case m := <-msgs:
				fmt.Sprintf("] " + m)
			case <-ctx.Done():
				return
			}
		}
	}()
	tb.Build(msgs)
	sol := tb.Result()
	if sol == nil {
		return &pb.BuildRTreeProofResponse{
			Error: ToError(wve.Err(wve.NoProofFound, "couldn't find a proof")),
		}, nil
	}
	resp := &pb.BuildRTreeProofResponse{
		Error: nil,
	}
	formalProof := serdes.WaveExplicitProof{}
	idx := 0
	expiry := time.Now()
	expiryset := false
	entities := make(map[string][]byte)
	refToIdx := make(map[string]int)
	for ref, edge := range sol.Set {
		refToIdx[ref] = idx
		var attref serdes.AttestationReference
		var err error
		attref.Content, err = edge.LRes.Attestation.DER()
		if err != nil {
			panic(err)
		}
		attref.Hash = *edge.LRes.Attestation.Keccak256HI().CanonicalForm()
		for _, kl := range edge.LRes.KnownLocations {
			attref.Locations = append(attref.Locations, *kl.CanonicalForm())
		}
		verifierKey := serdes.AVKeyAES128GCM(edge.LRes.Attestation.WR1Extra.VerifierBodyKey)
		attref.Keys = []asn1.External{asn1.NewExternal(verifierKey)}
		formalProof.Attestations = append(formalProof.Attestations, attref)
		if !expiryset || edge.LRes.Attestation.DecryptedBody.VerifierBody.Validity.NotAfter.Before(expiry) {
			expiry = edge.LRes.Attestation.DecryptedBody.VerifierBody.Validity.NotAfter
			expiryset = true
		}
		attesterhi, attesterloc, err := edge.LRes.Attestation.Attester()
		if err != nil {
			panic("why would this happen")
		}
		if _, ok := entities[attesterhi.MultihashString()]; !ok {
			entity, validity, err := eng.LookupEntity(ctx, attesterhi, attesterloc)
			if err != nil || !validity.Valid {
				return &pb.BuildRTreeProofResponse{
					Error: ToError(wve.Err(wve.NoProofFound, "proof expired while building")),
				}, nil
			}

			entities[entity.Keccak256HI().MultihashString()], err = entity.DER()
			if err != nil {
				panic(err)
			}
		}

		subjecthi, subjectloc := edge.LRes.Attestation.Subject()
		entity, validity, err := eng.LookupEntity(ctx, subjecthi, subjectloc)
		if err != nil || !validity.Valid {
			return &pb.BuildRTreeProofResponse{
				Error: ToError(wve.Err(wve.NoProofFound, "proof expired while building")),
			}, nil
		}
		entities[entity.Keccak256HI().MultihashString()], err = entity.DER()
		if err != nil {
			panic(err)
		}
		idx++
	}
	for _, path := range sol.Paths {
		formalpath := make([]int, len(path))
		for i, e := range path {
			formalpath[i] = refToIdx[e.Ref()]
		}
		formalProof.Paths = append(formalProof.Paths, formalpath)
	}
	for _, ent := range entities {
		formalProof.Entities = append(formalProof.Entities, ent)
	}
	wrappedFormalProof := serdes.WaveWireObject{
		Content: asn1.NewExternal(formalProof),
	}
	der, err := asn1.Marshal(wrappedFormalProof.Content)
	if err != nil {
		panic(err)
	}
	proof := &pb.Proof{
		Policy:   ToPbPolicy(sol.Policy()),
		Elements: make([]*pb.Attestation, 0, len(sol.Set)),
		Expiry:   expiry.UnixNano() / 1e6,
		Paths:    make([]*pb.ProofPath, len(formalProof.Paths)),
	}
	for idx, path := range formalProof.Paths {
		proof.Paths[idx] = &pb.ProofPath{}
		for _, pe := range path {
			proof.Paths[idx].Elements = append(proof.Paths[idx].Elements, int32(pe))
		}
	}
	for _, edge := range sol.Set {
		proof.Elements = append(proof.Elements, ConvertLookupResult(edge.LRes))
	}
	resp.Result = proof
	resp.ProofDER = der
	return resp, nil
}

func (e *EAPI) EncryptMessage(ctx context.Context, p *pb.EncryptMessageParams) (*pb.EncryptMessageResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.EncryptMessageResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	secret, err := ConvertEntitySecret(ctx, p.Perspective.EntitySecret)
	if err != nil {
		return &pb.EncryptMessageResponse{
			Error: ToError(err),
		}, nil
	}
	params := iapi.PEncryptMessage{
		Encryptor: secret,
	}
	if len(p.SubjectHash) != 0 {
		subHash := iapi.HashSchemeInstanceFromMultihash(p.SubjectHash)
		subLoc, err := LocationSchemeInstance(p.SubjectLocation)
		if err != nil {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not load subject location", err)),
			}, nil
		}
		if subLoc == nil {
			subLoc = iapi.SI().DefaultLocation(ctx)
		}
		sub, val, uerr := eng.LookupEntity(ctx, subHash, subLoc)
		if uerr != nil {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.ErrW(wve.LookupFailure, "could not resolve subject", uerr)),
			}, nil
		}
		if !val.Valid {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.Err(wve.LookupFailure, "subject entity is no longer valid")),
			}, nil
		}
		params.Subject = sub
	}
	if len(p.Namespace) != 0 {
		validFrom := TimeFromInt64MillisWithDefault(p.ValidFrom, time.Now())
		validUntil := TimeFromInt64MillisWithDefault(p.ValidUntil, time.Now())
		params.ValidAfter = validFrom
		params.ValidBefore = validUntil
		nsHash := iapi.HashSchemeInstanceFromMultihash(p.Namespace)
		nsLoc, err := LocationSchemeInstance(p.NamespaceLocation)
		if err != nil {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not parse namespace location", err)),
			}, nil
		}
		if nsLoc == nil {
			nsLoc = iapi.SI().DefaultLocation(ctx)
		}
		ns, val, uerr := eng.LookupEntity(ctx, nsHash, nsLoc)
		if uerr != nil {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.ErrW(wve.LookupFailure, "could not resolve namespace", uerr)),
			}, nil
		}
		if !val.Valid {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.Err(wve.LookupFailure, "namespace entity is no longer valid")),
			}, nil
		}
		params.Namespace = ns
		params.NamespaceLocation = nsLoc
		params.Resource = p.Resource
	}
	params.Content = p.Content
	rv, err := iapi.EncryptMessage(ctx, &params)
	if err != nil {
		return &pb.EncryptMessageResponse{
			Error: ToError(err),
		}, nil
	}
	return &pb.EncryptMessageResponse{
		Ciphertext: rv.Ciphertext,
	}, nil
}

func (e *EAPI) DecryptMessage(ctx context.Context, p *pb.DecryptMessageParams) (*pb.DecryptMessageResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.DecryptMessageResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	secret, err := ConvertEntitySecret(ctx, p.Perspective.EntitySecret)
	if err != nil {
		return &pb.DecryptMessageResponse{
			Error: ToError(err),
		}, nil
	}
	dctx := engine.NewEngineDecryptionContext(eng)
	dctx.AutoLoadPartitionSecrets(true)
	params := iapi.PDecryptMessage{
		Decryptor:  secret,
		Ciphertext: p.Ciphertext,
		Dctx:       dctx,
	}
	rv, err := iapi.DecryptMessage(ctx, &params)
	if err != nil {
		return &pb.DecryptMessageResponse{
			Error: ToError(err),
		}, nil
	}
	return &pb.DecryptMessageResponse{
		Content: rv.Content,
	}, nil

}

func (e *EAPI) ResolveName(ctx context.Context, p *pb.ResolveNameParams) (*pb.ResolveNameResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.ResolveNameResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	attester := eng.Perspective().Entity.Keccak256HI()
	if len(p.TopLevelAttester) > 0 {
		attester = iapi.HashSchemeInstanceFromMultihash(p.TopLevelAttester)
	}
	ndz, err := eng.LookupFullName(ctx, attester, p.Name)
	if err != nil {
		return &pb.ResolveNameResponse{
			Error: ToError(wve.ErrW(wve.LookupFailure, "name could not be resolved", err)),
		}, nil
	}
	if ndz == nil {
		return &pb.ResolveNameResponse{
			Error: ToError(wve.Err(wve.LookupFailure, "name could not be resolved")),
		}, nil
	}
	ent, val, uerr := eng.LookupEntity(ctx, ndz[0].Subject, ndz[0].SubjectLocation)
	if uerr != nil {
		return &pb.ResolveNameResponse{
			Error: ToError(wve.ErrW(wve.LookupFailure, "could not resolve subject", uerr)),
		}, nil
	}
	if ent == nil {
		return &pb.ResolveNameResponse{
			Error: ToError(wve.Err(wve.LookupFailure, "could not resolve subject")),
		}, nil
	}
	pbEnt := ConvertEntityWVal(ent, val)
	pbNDz := []*pb.NameDeclaration{}
	for _, nd := range ndz {
		pbNDz = append(pbNDz, ConvertNDWVal(nd, &engine.Validity{Valid: true}))
	}
	return &pb.ResolveNameResponse{
		Entity:     pbEnt,
		Derivation: pbNDz,
		Location:   ToPbLocation(ndz[0].SubjectLocation),
	}, nil
}

func (e *EAPI) CreateNameDeclaration(ctx context.Context, p *pb.CreateNameDeclarationParams) (*pb.CreateNameDeclarationResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	subloc, err := LocationSchemeInstance(p.SubjectLocation)
	if err != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create parse subject location", err)),
		}, nil
	}
	if subloc == nil {
		fmt.Printf("put in default location\n")
		subloc = iapi.SI().DefaultLocation(ctx)
	}
	sub := iapi.HashSchemeInstanceFromMultihash(p.Subject)
	subent, val, uerr := eng.LookupEntity(ctx, sub, subloc)
	if uerr != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not lookup subject entity", uerr)),
		}, nil
	}
	if subent == nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.Err(wve.LookupFailure, "could not lookup subject entity")),
		}, nil
	}
	if !val.Valid {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "subject entity is not valid")),
		}, nil
	}
	params := iapi.PCreateNameDeclaration{
		Attester:         eng.Perspective(),
		AttesterLocation: eng.PerspectiveLocation(),
		Subject:          subent,
		SubjectLocation:  subloc,
		Name:             p.Name,
	}
	if p.ValidFrom != 0 {
		t := time.Unix(0, p.ValidFrom*1e6)
		params.ValidFrom = &t
	}
	if p.ValidUntil != 0 {
		t := time.Unix(0, p.ValidUntil*1e6)
		params.ValidUntil = &t
	}
	if len(p.Namespace) > 0 {
		ns := iapi.HashSchemeInstanceFromMultihash(p.Namespace)
		nsloc, err := LocationSchemeInstance(p.NamespaceLocation)
		if err != nil {
			return &pb.CreateNameDeclarationResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create parse namespace location", err)),
			}, nil
		}
		if nsloc == nil {
			nsloc = iapi.SI().DefaultLocation(ctx)
		}
		nsent, val, uerr := eng.LookupEntity(ctx, ns, nsloc)
		if uerr != nil {
			return &pb.CreateNameDeclarationResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create namespace entity", uerr)),
			}, nil
		}
		if nsent == nil {
			return &pb.CreateNameDeclarationResponse{
				Error: ToError(wve.Err(wve.LookupFailure, "could not lookup namespace entity")),
			}, nil
		}
		if !val.Valid {
			return &pb.CreateNameDeclarationResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "namespace entity is not valid")),
			}, nil
		}
		params.Namespace = nsent
		params.NamespaceLocation = nsloc
		params.Partition = p.Partition
	}

	createrv, err := iapi.CreateNameDeclaration(ctx, &params)
	if err != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(err),
		}, nil
	}

	//Now publish it
	hash, uerr := iapi.SI().PutNameDeclaration(ctx, eng.PerspectiveLocation(), createrv.NameDeclaration)
	if uerr != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not add name declaration to storage", uerr)),
		}, nil
	}

	//Also publish reverse name
	err = eng.InsertReverseName(ctx, params.Name, params.Subject.Keccak256HI())
	if err != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.InternalError, "could not add name reverse name declaration", err)),
		}, nil
	}

	uerr = iapi.SI().Enqueue(ctx, eng.PerspectiveLocation(), eng.Perspective().Entity.Keccak256HI(), hash)
	if uerr != nil {
		return &pb.CreateNameDeclarationResponse{
			Error: ToError(wve.ErrW(wve.StorageError, "could not add name declaration to storage", uerr)),
		}, nil
	}

	return &pb.CreateNameDeclarationResponse{
		DER:  createrv.DER,
		Hash: hash.Multihash(),
	}, nil
}

func (e *EAPI) MarkEntityInteresting(ctx context.Context, p *pb.MarkEntityInterestingParams) (*pb.MarkEntityInterestingResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.MarkEntityInterestingResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	hi := iapi.HashSchemeInstanceFromMultihash(p.Entity)
	loc, err := LocationSchemeInstance(p.EntityLocation)
	if err != nil {
		return &pb.MarkEntityInterestingResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not parse location", err)),
		}, nil
	}
	ent, _, werr := eng.LookupEntity(ctx, hi, loc)
	if werr != nil {
		return &pb.MarkEntityInterestingResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not lookup entity", werr)),
		}, nil
	}
	if ent == nil {
		return &pb.MarkEntityInterestingResponse{
			Error: ToError(wve.Err(wve.LookupFailure, "could not find entity")),
		}, nil
	}
	werr = eng.MarkEntityInterestingAndQueueForSync(ent, loc)
	if werr != nil {
		return &pb.MarkEntityInterestingResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not mark entity interesting", werr)),
		}, nil
	}
	return &pb.MarkEntityInterestingResponse{}, nil
}

func (e *EAPI) ResolveReverseName(ctx context.Context, p *pb.ResolveReverseNameParams) (*pb.ResolveReverseNameResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.ResolveReverseNameResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}
	hi := iapi.HashSchemeInstanceFromMultihash(p.Hash)
	if !hi.Supported() {
		return &pb.ResolveReverseNameResponse{
			Error: ToError(wve.Err(wve.InvalidParameter, "bad hash")),
		}, nil
	}
	rv, err := eng.LookupReverseName(ctx, hi)
	if err != nil {
		return &pb.ResolveReverseNameResponse{
			Error: ToError(wve.ErrW(wve.InternalError, "could not perform lookup", err)),
		}, nil
	}
	if rv == "" {
		return &pb.ResolveReverseNameResponse{
			Error: ToError(wve.Err(wve.LookupFailure, "could not reverse resolve name")),
		}, nil
	}
	return &pb.ResolveReverseNameResponse{
		Name: rv,
	}, nil
}

func (e *EAPI) Revoke(ctx context.Context, p *pb.RevokeParams) (*pb.RevokeResponse, error) {
	eng, err := e.getEngine(ctx, p.Perspective)
	if err != nil {
		return &pb.RevokeResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", err)),
		}, nil
	}

	//Attestation
	if len(p.AttestationHash) != 0 {
		hi := iapi.HashSchemeInstanceFromMultihash(p.AttestationHash)
		if !hi.Supported() {
			return &pb.RevokeResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "invalid attestation hash")),
			}, nil
		}

		reglocs, err := iapi.SI().RegisteredLocations(ctx)
		if err != nil {
			panic(err)
		}
		found := false
		for _, loc := range reglocs {
			att, _, err := eng.LookupAttestationNoPerspective(ctx, hi, nil, loc)
			if err != nil {
				return &pb.RevokeResponse{
					Error: ToError(wve.ErrW(wve.LookupFailure, "could not lookup attestation", err)),
				}, nil
			}
			if att == nil {
				continue
			}
			found = true
			if len(att.Revocations) == 0 {
				return &pb.RevokeResponse{
					Error: ToError(wve.Err(wve.InvalidParameter, "attestation has no revocation options")),
				}, nil
			}
			rvk, loc, werr := eng.Perspective().AttestationRevocationDetails(att)
			if werr != nil {
				return &pb.RevokeResponse{
					Error: ToError(werr),
				}, nil
			}
			fmt.Printf("put the revocation blob\n")
			_, err = iapi.SI().PutBlob(ctx, loc, rvk)
			if err != nil {
				return &pb.RevokeResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "could not publish revocation", err)),
				}, nil
			}
			break //only one publish is required
		}
		if !found {
			return &pb.RevokeResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "no attestation with that hash found")),
			}, nil
		}
	} //end attestation

	//Name deckaration
	if len(p.NameDeclarationHash) != 0 {
		hi := iapi.HashSchemeInstanceFromMultihash(p.NameDeclarationHash)
		if !hi.Supported() {
			return &pb.RevokeResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "invalid name declaration hash")),
			}, nil
		}

		reglocs, err := iapi.SI().RegisteredLocations(ctx)
		if err != nil {
			panic(err)
		}
		found := false
		for _, loc := range reglocs {
			nd, _, err := eng.LookupNameDeclaration(ctx, hi, loc)
			if err != nil {
				return &pb.RevokeResponse{
					Error: ToError(wve.ErrW(wve.LookupFailure, "could not lookup name declaration", err)),
				}, nil
			}
			if nd == nil {
				continue
			}
			found = true
			if len(nd.Revocations) == 0 {
				return &pb.RevokeResponse{
					Error: ToError(wve.Err(wve.InvalidParameter, "name declaration has no revocation options")),
				}, nil

			}
			rvk, loc, werr := eng.Perspective().NameDeclarationRevocationDetails(nd)
			if werr != nil {
				return &pb.RevokeResponse{
					Error: ToError(werr),
				}, nil
			}
			_, err = iapi.SI().PutBlob(ctx, loc, rvk)
			if err != nil {
				fmt.Printf("the location in question was: %v\n", loc)
				return &pb.RevokeResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "could not publish revocation", err)),
				}, nil
			}
			break //only one publish is required
		}
		if !found {
			return &pb.RevokeResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "no attestation with that hash found")),
			}, nil
		}
	} //end attestation

	//Entity
	if p.RevokePerspective {
		fmt.Printf("revoking perspective\n")
		if len(eng.Perspective().Entity.Revocations) == 0 {
			return &pb.RevokeResponse{
				Error: ToError(wve.Err(wve.InvalidParameter, "entity has no revocation options")),
			}, nil
		}
		rvk, locz := eng.Perspective().CommitmentRevocationDetails()
		for _, loc := range locz {
			_, err := iapi.SI().PutBlob(ctx, loc, rvk)
			if err != nil {
				return &pb.RevokeResponse{
					Error: ToError(wve.ErrW(wve.InternalError, "could not publish revocation", err)),
				}, nil
			}
		}
	} //end entity

	eng.ResetRevocationCache(ctx)

	return &pb.RevokeResponse{}, nil
}

func (e *EAPI) CompactProof(ctx context.Context, p *pb.CompactProofParams) (*pb.CompactProofResponse, error) {
	rv, err := iapi.CompactProof(ctx, &iapi.PCompactProof{
		DER: p.DER,
	})
	if err != nil {
		return &pb.CompactProofResponse{
			Error: ToError(err),
		}, nil
	}
	return &pb.CompactProofResponse{
		ProofDER: rv.DER,
	}, nil
}
