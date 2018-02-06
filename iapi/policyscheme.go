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
		return &TrustLevelPolicy{canonicalForm: *e, Trust: e.Content.(serdes.TrustLevel).Trust}, nil
	}
	return &UnsupportedPolicySchemeInstance{*e}, nil
}

var _ PolicySchemeInstance = &UnsupportedPolicySchemeInstance{}

type UnsupportedPolicySchemeInstance struct {
	canonicalForm asn1.External
}

func (ps *UnsupportedPolicySchemeInstance) Supported() bool {
	return false
}
func (ps *UnsupportedPolicySchemeInstance) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	return &ps.canonicalForm, nil
}
func (ps *UnsupportedPolicySchemeInstance) WR1DomainEntity(ctx context.Context) (HashScheme, error) {
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
	return &TrustLevelPolicy{canonicalForm: asn1.NewExternal(cf), Trust: trust}, nil
}

type TrustLevelPolicy struct {
	canonicalForm asn1.External
	Trust         int
}

func (ps *TrustLevelPolicy) Supported() bool {
	return true
}
func (ps *TrustLevelPolicy) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	return &ps.canonicalForm, nil
}

func (ps *TrustLevelPolicy) WR1DomainEntity(ctx context.Context) (HashScheme, error) {
	return nil, nil
}
func (ps *TrustLevelPolicy) WR1Partition(ctx context.Context) ([][]byte, error) {
	return make([][]byte, 20), nil
}
