package dot

import (
	"context"
	"fmt"

	"github.com/immesys/wave/dot/objs"
	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/params"
	"github.com/immesys/wave/policy"
)

type CreateDOTParams struct {
	Granter   *entity.Entity
	Recipient *entity.Entity
	Policy    policy.Policy
}

func CreateDOT(ctx *context.Context, p *CreateDOTParams) (*DOT, error) {
	rv := DOT{Content: &objs.DOTContent{}, PlaintextHeader: &objs.PlaintextHeader{}, Inheritance: &objs.InheritanceMap{}}
	rv.Content.SRC = p.Granter.Hash
	rv.Content.DST = p.Recipient.Hash
	rv.Content.NS = p.Policy.Namespace()
	rv.Content.Permissions = p.Policy.Permissions()
	rv.Content.URI = p.Policy.URI()
	if len(rv.Content.URI) == 0 || rv.Content.URI[0] != '/' {
		return nil, fmt.Errorf("invalid uri suffix %q", rv.Content.URI)
	}
	rv.PlaintextHeader.DST = p.Recipient.Hash
	if len(p.Policy.PartitionID()) != params.OAQUESlots {
		return nil, fmt.Errorf("invalid number of slots")
	}
	if len(p.Policy.PartitionLabelID()) != params.OAQUESlots {
		return nil, fmt.Errorf("invalid number of slots")
	}
	rv.PartitionLabel = p.Policy.PartitionID()

	return &rv, nil
}
