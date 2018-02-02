package iapi

import "context"

type IAPIs struct {
}

type PNewEntity struct {
	SkipWR1Keys bool
	Contact     string
	Comment     string
}
type RNewEntity struct {
	InEntity *InEntity
}

func (iapi *IAPIs) NewEntity(ctx context.Context, p *PNewEntity) (*RNewEntity, error) {

}
