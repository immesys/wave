package eapi

import (
	"context"
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
	secret, err := ConvertEntitySecret(ctx, in.EntitySecret)
	if err != nil {
		return nil, err
	}
	loc, err := LocationSchemeInstance(in.Location)
	if err != nil {
		return nil, err
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
	return eng, nil
}
func (e *EAPI) getEngineNoPerspective() *engine.Engine {
	return e.npengine
}
func (e *EAPI) Inspect(ctx context.Context, p *pb.InspectParams) (*pb.InspectResponse, error) {
	eng := e.getEngineNoPerspective()
	//Try as entitysecret
	es, err := iapi.ParseEntitySecrets(ctx, &iapi.PParseEntitySecrets{
		DER: p.Content,
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
		DER:               p.Content,
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
	secret, err := ConvertEntitySecret(ctx, p.Perspective.EntitySecret)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	loc, err := LocationSchemeInstance(p.Perspective.Location)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "bad perspective location", err)),
		}, nil
	}
	hashScheme, uerr := iapi.SI().HashSchemeFor(loc)
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(wve.ErrW(wve.UnsupportedHashScheme, "could not get hash scheme for location", err)),
		}, nil
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
	if err != nil {
		return &pb.CreateAttestationResponse{
			Error: ToError(err),
		}, nil
	}
	hi := iapi.KECCAK256.Instance(resp.DER)
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
	loc, err := LocationSchemeInstance(p.Location)
	if err != nil {
		return &pb.PublishAttestationResponse{
			Error: ToError(err),
		}, nil
	}
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

func (e *EAPI) VerifyProof(ctx context.Context, p *pb.VerifyProofParams) (*pb.VerifyProofResponse, error) {
	resp, werr := iapi.VerifyRTreeProof(ctx, &iapi.PVerifyRTreeProof{
		DER: p.ProofDER,
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
func (e *EAPI) BuildRTreeProof(ctx context.Context, p *pb.BuildRTreeParams) (*pb.BuildRTreeResponse, error) {
	eng, werr := e.getEngine(ctx, p.Perspective)
	if werr != nil {
		return &pb.BuildRTreeResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "could not create perspective", werr)),
		}, nil
	}
	spol := serdes.RTreePolicy{}
	ehash := iapi.HashSchemeInstanceFromMultihash(p.RtreeNamespace)
	if !ehash.Supported() {
		return &pb.BuildRTreeResponse{
			Error: ToError(wve.ErrW(wve.InvalidParameter, "bad namespace", werr)),
		}, nil
	}
	ext := ehash.CanonicalForm()
	spol.Namespace = *ext
	for _, st := range p.Statements {
		pset := iapi.HashSchemeInstanceFromMultihash(st.PermissionSet)
		if !pset.Supported() {
			return &pb.BuildRTreeResponse{
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
		return &pb.BuildRTreeResponse{
			Error: ToError(wve.Err(wve.NoProofFound, "could find a proof")),
		}, nil
	}
	resp := &pb.BuildRTreeResponse{
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
		}
		attesterhi, attesterloc, err := edge.LRes.Attestation.Attester()
		if err != nil {
			panic("why would this happen")
		}
		if _, ok := entities[attesterhi.MultihashString()]; !ok {
			entity, validity, err := eng.LookupEntity(ctx, attesterhi, attesterloc)
			if err != nil || !validity.Valid {
				return &pb.BuildRTreeResponse{
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
			return &pb.BuildRTreeResponse{
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
		nsHash := iapi.HashSchemeInstanceFromMultihash(p.Namespace)
		nsLoc, err := LocationSchemeInstance(p.NamespaceLocation)
		if err != nil {
			return &pb.EncryptMessageResponse{
				Error: ToError(wve.ErrW(wve.InvalidParameter, "could not parse namespace location", err)),
			}, nil
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
		params.Partition = p.Partition
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
