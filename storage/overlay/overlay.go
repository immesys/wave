package overlay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/simplehttp"
	"github.com/immesys/wave/wve"
)

type Overlay struct {
	providers map[string]iapi.StorageDriverInterface
}

//config is a map of name->config map
func NewOverlay(config map[string]map[string]string) (iapi.StorageInterface, error) {
	rv := &Overlay{providers: make(map[string]iapi.StorageDriverInterface)}
	foundDefault := false
	for name, cfg := range config {
		switch cfg["provider"] {
		case "http_v1":
			driver := &simplehttp.SimpleHTTPStorage{}
			err := driver.Initialize(context.Background(), name, cfg)
			if err != nil {
				return nil, fmt.Errorf("storage driver %s::%s error: %s", cfg["provider"], name, err)
			}
			rv.providers[name] = driver
		case "":
			return nil, fmt.Errorf("storage driver %q has no provider field", name)
		default:
			return nil, fmt.Errorf("storage driver type %q unknown", cfg["provider"])
		}
		if name == "default" {
			foundDefault = true
		}
	}
	if !foundDefault {
		return nil, fmt.Errorf("storage config missing default provider")
	}
	return rv, nil
}

func (ov *Overlay) LocationByName(ctx context.Context, name string) (iapi.LocationSchemeInstance, error) {
	driver, ok := ov.providers[name]
	if !ok {
		return nil, fmt.Errorf("location %q is not registered on this agent", name)
	}
	return driver.Location(ctx), nil
}

func (ov *Overlay) DefaultLocation(ctx context.Context) iapi.LocationSchemeInstance {
	rv, err := ov.LocationByName(ctx, "default")
	if err != nil {
		panic("trouble getting default location")
	}
	return rv
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
func (ov *Overlay) Status(ctx context.Context) (map[string]iapi.StorageDriverStatus, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	rv := make(map[string]iapi.StorageDriverStatus)
	for name, driver := range ov.providers {
		operating, stat, err := driver.Status(ctx)
		if err != nil {
			return nil, err
		}
		rv[name] = iapi.StorageDriverStatus{
			Operational: operating,
			Info:        stat,
		}
	}
	return rv, nil
}

func (ov *Overlay) PutBlob(ctx context.Context, loc iapi.LocationSchemeInstance, content []byte) (iapi.HashSchemeInstance, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	return p.Put(sctx, content)
}
func (ov *Overlay) GetBlob(ctx context.Context, loc iapi.LocationSchemeInstance, hash iapi.HashSchemeInstance) ([]byte, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	return p.Get(sctx, hash)
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

func (ov *Overlay) GetAttestationOrDeclaration(ctx context.Context, loc iapi.LocationSchemeInstance, hash iapi.HashSchemeInstance) (*iapi.GetResult, error) {
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
	rpa, werr := iapi.ParseAttestation(sctx, &iapi.PParseAttestation{
		DER: der,
	})
	if werr != nil && werr.Code() == wve.UnexpectedObject {
		//Try parse as name declaration
		nda, err := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
			DER: der,
		})
		if err != nil {
			return nil, err
		}
		if nda.IsMalformed {
			return nil, errors.New("object is malformed")
		}
		return &iapi.GetResult{
			NameDeclaration: nda.Result,
		}, nil
	}
	if werr != nil {
		return nil, werr
	}
	if rpa.IsMalformed {
		return nil, errors.New("Attestation is malformed")
	}
	return &iapi.GetResult{
		Attestation: rpa.Attestation,
	}, nil
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
func (ov *Overlay) PutNameDeclaration(ctx context.Context, loc iapi.LocationSchemeInstance, nd *iapi.NameDeclaration) (iapi.HashSchemeInstance, error) {
	sctx, scancel := context.WithTimeout(ctx, MaximumTimeout)
	defer scancel()
	p, err := ov.getProvider(sctx, loc)
	if err != nil {
		return nil, err
	}
	der, err := nd.DER()
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
func (ov *Overlay) RegisteredLocations(ctx context.Context) (map[string]iapi.LocationSchemeInstance, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	rv := make(map[string]iapi.LocationSchemeInstance)
	for name, driver := range ov.providers {
		rv[name] = driver.Location(ctx)
	}
	return rv, nil
}
