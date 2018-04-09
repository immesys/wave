package eapi

import (
	"context"
	"encoding/asn1"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

func TimeFromInt64MillisWithDefault(v int64, def time.Time) *time.Time {
	if v == 0 {
		return &def
	}
	t := time.Unix(0, v*100000)
	return &t
}

func LocationSchemeInstance(in *pb.Location) (iapi.LocationSchemeInstance, wve.WVE) {
	if in == nil {
		return nil, nil
	}
	switch {
	case in.LocationURI != nil:
		return iapi.NewLocationSchemeInstanceURL(in.LocationURI.URI, int(in.LocationURI.Version)), nil
	case in.AgentLocation != "":
		rv, err := iapi.SI().LocationByName(context.Background(), in.AgentLocation)
		if err != nil {
			return nil, wve.ErrW(wve.UnsupportedLocationScheme, "bad agent location", err)
		}
		return rv, nil
	default:
		return nil, wve.Err(wve.UnsupportedLocationScheme, "unknown location")
	}
}
func ToPbLocation(in iapi.LocationSchemeInstance) *pb.Location {
	locuri, ok := in.(*iapi.LocationSchemeInstanceURL)
	if !ok {
		return nil
	}
	return &pb.Location{
		LocationURI: &pb.LocationURI{
			URI:     locuri.SerdesForm.Value,
			Version: int32(locuri.SerdesForm.Version),
		},
	}
}
func ToPbPolicy(in iapi.PolicySchemeInstance) *pb.Policy {
	if tl, ok := in.(*iapi.TrustLevelPolicy); ok {
		return &pb.Policy{
			TrustLevelPolicy: &pb.TrustLevelPolicy{
				Trust: int32(tl.Trust),
			},
		}
	}
	if rt, ok := in.(*iapi.RTreePolicy); ok {
		rtp := &pb.RTreePolicy{
			Namespace:     rt.WR1DomainEntity().Multihash(),
			Indirections:  uint32(rt.SerdesForm.Indirections),
			VisibilityURI: rt.WR1Partition(),
		}
		for _, st := range rt.SerdesForm.Statements {
			rtp.Statements = append(rtp.Statements, &pb.RTreePolicyStatement{
				PermissionSet: iapi.HashSchemeInstanceFor(&st.PermissionSet).Multihash(),
				Permissions:   st.Permissions,
				Resource:      st.Resource,
			})
		}
		rv := &pb.Policy{
			RTreePolicy: rtp,
		}
		return rv
	}
	return nil
}
func ToError(e wve.WVE) *pb.Error {
	if e == nil {
		return nil
	}
	return &pb.Error{
		Code:    int32(e.Code()),
		Message: e.Error(),
	}
}
func ConvertHashScheme(in string) iapi.HashScheme {
	if in == serdes.Sha3_256OID.String() {
		return iapi.SHA3
	}
	if in == serdes.Keccak_256OID.String() {
		return iapi.KECCAK256
	}
	return &iapi.UnsupportedHashScheme{}
}
func ConvertProofAttestation(a *iapi.Attestation) *pb.Attestation {
	rv := pb.Attestation{}
	rv.Validity = &pb.AttestationValidity{
		Valid: true,
	}
	der, err := a.DER()
	if err != nil {
		panic(err)
	}
	rv.DER = der
	rv.Hash = a.Keccak256HI().Multihash()
	if a.WR1Extra != nil {
		rv.VerifierKey = a.WR1Extra.VerifierBodyKey
		rv.ProverKey = a.WR1Extra.ProverBodyKey
	}
	subjHI, subjLoc := a.Subject()
	rv.SubjectHash = subjHI.Multihash()
	rv.SubjectLocation = ToPbLocation(subjLoc)

	if a.DecryptedBody != nil {
		rv.Body = &pb.AttestationBody{}
		decder, err := asn1.Marshal(*a.DecryptedBody)
		if err != nil {
			panic(err)
		}
		rv.Body.DecodedBodyDER = decder
		attHI, attLoc, err := a.Attester()
		if err != nil {
			panic(err)
		}
		rv.Body.AttesterHash = attHI.Multihash()
		rv.Body.AttesterLocation = ToPbLocation(attLoc)
		rv.Body.ValidFrom = a.DecryptedBody.VerifierBody.Validity.NotBefore.UnixNano()
		rv.Body.ValidUntil = a.DecryptedBody.VerifierBody.Validity.NotAfter.UnixNano()
		pol, err := iapi.PolicySchemeInstanceFor(&a.DecryptedBody.VerifierBody.Policy)
		if err != nil {
			panic(err)
		}
		rv.Body.Policy = ToPbPolicy(pol)
	}
	return &rv
}
func ConvertLookupResult(r *engine.LookupResult) *pb.Attestation {
	rv := pb.Attestation{}
	rv.Validity = &pb.AttestationValidity{
		Valid:        r.Validity.Valid,
		Revoked:      r.Validity.Revoked,
		Expired:      r.Validity.Expired,
		Malformed:    r.Validity.Malformed,
		NotDecrypted: r.Validity.NotDecrypted,
		SrcInvalid:   r.Validity.SrcInvalid,
		DstInvalid:   r.Validity.DstInvalid,
		Message:      r.Validity.Message,
	}
	der, err := r.Attestation.DER()
	if err != nil {
		panic(err)
	}
	rv.DER = der
	rv.Hash = r.Attestation.Keccak256HI().Multihash()
	if r.Attestation.WR1Extra != nil {
		rv.VerifierKey = r.Attestation.WR1Extra.VerifierBodyKey
		rv.ProverKey = r.Attestation.WR1Extra.ProverBodyKey
	}
	subjHI, subjLoc := r.Attestation.Subject()
	rv.SubjectHash = subjHI.Multihash()
	rv.SubjectLocation = ToPbLocation(subjLoc)

	if r.Attestation.DecryptedBody != nil {
		rv.Body = &pb.AttestationBody{}
		decder, err := asn1.Marshal(*r.Attestation.DecryptedBody)
		if err != nil {
			panic(err)
		}
		rv.Body.DecodedBodyDER = decder
		attHI, attLoc, err := r.Attestation.Attester()
		if err != nil {
			panic(err)
		}
		rv.Body.AttesterHash = attHI.Multihash()
		rv.Body.AttesterLocation = ToPbLocation(attLoc)
		rv.Body.ValidFrom = r.Attestation.DecryptedBody.VerifierBody.Validity.NotBefore.UnixNano()
		rv.Body.ValidUntil = r.Attestation.DecryptedBody.VerifierBody.Validity.NotAfter.UnixNano()
		pol, err := iapi.PolicySchemeInstanceFor(&r.Attestation.DecryptedBody.VerifierBody.Policy)
		if err != nil {
			panic(err)
		}
		rv.Body.Policy = ToPbPolicy(pol)
	}
	return &rv
}

// func ToPbHash(in iapi.HashSchemeInstance) *pb.Hash {
// 	rv := &pb.Hash{}
// 	if sha3, ok := in.(*iapi.HashSchemeInstance_Sha3_256); ok {
// 		rv.Sha3_256 = sha3.Value()
// 		return rv
// 	}
// 	if keccak, ok := in.(*iapi.HashSchemeInstance_Keccak_256); ok {
// 		rv.Keccak256 = keccak.Value()
// 		return rv
// 	}
// 	panic("unknown hash")
// }
func ConvertPolicy(in *pb.Policy) iapi.PolicySchemeInstance {
	if in == nil {
		panic("nil policy")
	}
	if in.TrustLevelPolicy != nil {
		rv, err := iapi.NewTrustLevelPolicy(int(in.TrustLevelPolicy.Trust))
		if err != nil {
			panic(err)
		}
		return rv
	}
	if in.RTreePolicy != nil {
		spol := serdes.RTreePolicy{
			Indirections: int(in.RTreePolicy.Indirections),
		}
		ehash := iapi.HashSchemeInstanceFromMultihash(in.RTreePolicy.Namespace)
		ext := ehash.CanonicalForm()
		spol.Namespace = *ext
		for _, st := range in.RTreePolicy.Statements {
			pset := iapi.HashSchemeInstanceFromMultihash(st.PermissionSet)
			ext := pset.CanonicalForm()
			spol.Statements = append(spol.Statements, serdes.RTreeStatement{
				Permissions:   st.Permissions,
				PermissionSet: *ext,
				Resource:      st.Resource,
			})
		}
		rv, err := iapi.NewRTreePolicyScheme(spol, in.RTreePolicy.VisibilityURI)
		if err != nil {
			panic(err)
		}
		return rv
	}
	panic("unknown policy")
}
func ConvertBodyScheme(in string) iapi.AttestationBodyScheme {
	if in == serdes.UnencryptedBodyOID.String() {
		return &iapi.PlaintextBodyScheme{}
	}
	if in == serdes.WR1BodyOID.String() {
		return &iapi.WR1BodyScheme{}
	}
	panic("unknown body scheme")
}
func ConvertEntitySecret(ctx context.Context, in *pb.EntitySecret) (*iapi.EntitySecrets, wve.WVE) {
	passphrase := string(in.Passphrase)
	ppae, err := iapi.ParseEntitySecrets(ctx, &iapi.PParseEntitySecrets{
		DER:        in.DER,
		Passphrase: &passphrase,
	})
	if err != nil {
		return nil, err
	}
	return ppae.EntitySecrets, nil
}
