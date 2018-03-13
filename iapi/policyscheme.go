package iapi

import (
	"context"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

func PolicySchemeInstanceFor(e *asn1.External) (PolicySchemeInstance, error) {
	switch {
	case e.OID.Equal(serdes.TrustLevelPolicyOID):
		return &TrustLevelPolicy{SerdesForm: *e, Trust: e.Content.(serdes.TrustLevel).Trust}, nil
	case e.OID.Equal(serdes.ResourceTreePolicyOID):
		rtp, ok := e.Content.(serdes.RTreePolicy)
		if !ok {
			return &UnsupportedPolicySchemeInstance{*e}, nil
		}
		return &RTreePolicy{SerdesForm: rtp}, nil
	}
	return &UnsupportedPolicySchemeInstance{*e}, nil
}

var _ PolicySchemeInstance = &UnsupportedPolicySchemeInstance{}

type UnsupportedPolicySchemeInstance struct {
	SerdesForm asn1.External
}

func (ps *UnsupportedPolicySchemeInstance) Supported() bool {
	return false
}
func (ps *UnsupportedPolicySchemeInstance) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	return &ps.SerdesForm, nil
}
func (ps *UnsupportedPolicySchemeInstance) WR1DomainEntity(ctx context.Context) (HashSchemeInstance, error) {
	return nil, fmt.Errorf("this policy scheme is not supported")
}
func (ps *UnsupportedPolicySchemeInstance) WR1Partition(ctx context.Context) ([][]byte, error) {
	return nil, fmt.Errorf("this policy scheme is not supported")
}

var _ PolicySchemeInstance = &TrustLevelPolicy{}

func NewTrustLevelPolicy(trust int) (*TrustLevelPolicy, error) {
	if trust < 0 || trust > 4 {
		return nil, fmt.Errorf("trust must be between 0 and 4 inclusive")
	}
	cf := serdes.TrustLevel{Trust: trust}
	return &TrustLevelPolicy{SerdesForm: asn1.NewExternal(cf), Trust: trust}, nil
}

type TrustLevelPolicy struct {
	SerdesForm asn1.External
	Trust      int
}

func (ps *TrustLevelPolicy) Supported() bool {
	return true
}
func (ps *TrustLevelPolicy) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	return &ps.SerdesForm, nil
}

func (ps *TrustLevelPolicy) WR1DomainEntity(ctx context.Context) (HashSchemeInstance, error) {
	return nil, nil
}
func (ps *TrustLevelPolicy) WR1Partition(ctx context.Context) ([][]byte, error) {
	return make([][]byte, 20), nil
}

type RTreePolicy struct {
	SerdesForm    serdes.RTreePolicy
	VisibilityURI [][]byte
}

func NewRTreePolicyScheme(policy serdes.RTreePolicy, visuri [][]byte) (*RTreePolicy, error) {
	if len(visuri) > 20 {
		return nil, fmt.Errorf("too many elements in visibility URI")
	}
	vuri := make([][]byte, 20)
	for idx, p := range visuri {
		vuri[idx] = p
	}
	return &RTreePolicy{
		SerdesForm:    policy,
		VisibilityURI: vuri,
	}, nil
}

func (ps *RTreePolicy) Supported() bool {
	return true
}
func (ps *RTreePolicy) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	ext := asn1.NewExternal(ps.SerdesForm)
	return &ext, nil
}

func (ps *RTreePolicy) WR1DomainEntity(ctx context.Context) (HashSchemeInstance, error) {
	return HashSchemeInstanceFor(&ps.SerdesForm.Namespace), nil
}
func (ps *RTreePolicy) WR1Partition(ctx context.Context) ([][]byte, error) {
	return ps.VisibilityURI, nil
}
