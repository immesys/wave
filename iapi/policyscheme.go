package iapi

import (
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
func (ps *UnsupportedPolicySchemeInstance) CanonicalForm() *asn1.External {
	return &ps.SerdesForm
}
func (ps *UnsupportedPolicySchemeInstance) WR1DomainEntity() HashSchemeInstance {
	panic("WR1DomainEntity() called on unsupported policy")
}
func (ps *UnsupportedPolicySchemeInstance) WR1Partition() [][]byte {
	panic("WR1Partition() called on unsupported policy")
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
func (ps *TrustLevelPolicy) CanonicalForm() *asn1.External {
	return &ps.SerdesForm
}

func (ps *TrustLevelPolicy) WR1DomainEntity() HashSchemeInstance {
	return nil
}
func (ps *TrustLevelPolicy) WR1Partition() [][]byte {
	return make([][]byte, 20)
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
func (ps *RTreePolicy) CanonicalForm() *asn1.External {
	ext := asn1.NewExternal(ps.SerdesForm)
	return &ext
}

func (ps *RTreePolicy) WR1DomainEntity() HashSchemeInstance {
	return HashSchemeInstanceFor(&ps.SerdesForm.Namespace)
}
func (ps *RTreePolicy) WR1Partition() [][]byte {
	return ps.VisibilityURI
}
