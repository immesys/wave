package eapi

import (
	"context"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
)

func PbHashToHashSchemeInstance(h *pb.Hash) (iapi.HashSchemeInstance, error) {
	panic("ni")
}

func TimeFromInt64MillisWithDefault(v int64, def time.Time) *time.Time {
	if v == 0 {
		return &def
	}
	t := time.Unix(0, v*100000)
	return &t
}

func LocationSchemeInstance(in *pb.Location) iapi.LocationSchemeInstance {
	if in == nil {
		return nil
	}
	if in.LocationURI == nil {
		return &iapi.UnsupportedLocationSchemeInstance{}
	}
	return iapi.NewLocationSchemeInstanceURL(in.LocationURI.URI, int(in.LocationURI.Version))
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

func ToPbHash(in iapi.HashSchemeInstance) *pb.Hash {
	rv := &pb.Hash{}
	if sha3, ok := in.(*iapi.HashSchemeInstance_Sha3_256); ok {
		rv.Sha3_256 = sha3.Value()
		return rv
	}
	if keccak, ok := in.(*iapi.HashSchemeInstance_Keccak_256); ok {
		rv.Keccak256 = keccak.Value()
		return rv
	}
	panic("unknown hash")
}
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
		ehash := ConvertHashSchemeInstance(in.RTreePolicy.Namespace)
		ext, err := ehash.CanonicalForm()
		if err != nil {
			panic(err)
		}
		spol.Namespace = *ext
		for _, st := range in.RTreePolicy.Statements {
			pset := ConvertHashSchemeInstance(st.PermissionSet)
			ext, err := pset.CanonicalForm()
			if err != nil {
				panic(err)
			}
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
func ConvertHashSchemeInstance(in *pb.Hash) iapi.HashSchemeInstance {
	if in.Sha3_256 != nil {
		return &iapi.HashSchemeInstance_Sha3_256{Val: in.Sha3_256}
	}
	if in.Keccak256 != nil {
		return &iapi.HashSchemeInstance_Keccak_256{Val: in.Keccak256}
	}
	panic("unknown hash scheme")
}
func ConvertEntitySecret(ctx context.Context, in *pb.EntitySecret) *iapi.EntitySecrets {
	passphrase := string(in.Passphrase)
	ppae, err := iapi.ParseEntitySecrets(ctx, &iapi.PParseEntitySecrets{
		DER:        in.DER,
		Passphrase: &passphrase,
	})
	if err != nil {
		panic(err)
	}
	return ppae.EntitySecrets
}
