package overlay

import (
	"context"
	"errors"
	"time"

	"github.com/immesys/wave/iapi"
)

type Overlay struct {
	providers []iapi.StorageDriverInterface
}

func NewOverlay(config map[string]map[string]string) {

}

var MaximumTimeout = 5 * time.Second
var ErrUnknownLocation = errors.New("unknown location")

func (ov *Overlay) getProvider(ctx context.Context, loc iapi.LocationSchemeInstance) (iapi.StorageDriverInterface, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for _, p := range ov.providers {
		if p.Location(ctx).Equal(loc) {
			return p, nil
		}
	}
	return nil, ErrUnknownLocation
}
func (ov *Overlay) GetEntity(ctx context.Context, loc iapi.LocationSchemeInstance, hash iapi.HashSchemeInstance) (*iapi.Entity, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	der, err := p.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	rpe, err := iapi.ParseEntity(sctx, &iapi.PParseEntity{
		DER: der,
	})
	if err != nil {
		return nil, err
	}
	return rpe.Entity, nil
}
func (ov *Overlay) PutEntity(ctx context.Context, loc iapi.LocationSchemeInstance, ent *iapi.Entity) (iapi.HashSchemeInstance, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	der, err := ent.DER()
	if err != nil {
		return nil, err
	}
	return p.Put(sctx, der)
}
func (ov *Overlay) GetAttestation(ctx context.Context, loc iapi.LocationSchemeInstance, hash iapi.HashSchemeInstance) (*iapi.Attestation, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	der, err := p.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	rpa, err := iapi.ParseAttestation(sctx, &iapi.PParseAttestation{
		DER: der,
	})
	if err != nil {
		return nil, err
	}
	if rpa.IsMalformed {
		return nil, errors.New("Attestation is malformed")
	}
	return rpa.Attestation, nil
}
func (ov *Overlay) PutAttestation(ctx context.Context, loc iapi.LocationSchemeInstance, att *iapi.Attestation) (iapi.HashSchemeInstance, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	der, err := att.DER()
	if err != nil {
		return nil, err
	}
	return p.Put(sctx, der)
}
func (ov *Overlay) IterateQeueue(ctx context.Context, loc iapi.LocationSchemeInstance, queueId iapi.HashSchemeInstance, token string) (object iapi.HashSchemeInstance, nextToken string, err error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, "", err
	}
	return p.IterateQueue(sctx, queueId, token)
}
func (ov *Overlay) Enqueue(ctx context.Context, loc iapi.LocationSchemeInstance, queueId iapi.HashSchemeInstance, object iapi.HashSchemeInstance) error {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return err
	}
	return p.Enqueue(sctx, queueId, object)
}
func (ov *Overlay) HashSchemeFor(loc iapi.LocationSchemeInstance) (iapi.HashScheme, error) {
	p, err := ov.getProvider(context.Background(), loc)
	if err != nil {
		return nil, err
	}
	return p.PreferredHashScheme(), nil
}
