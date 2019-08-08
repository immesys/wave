package jedistore

import (
	"context"
	"errors"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
	"github.com/ucbrise/jedi-protocol-go"
)

// WAVEPublicInfo implements the jedi.PublicInfoReader interface. It lifts the
// view of WAVE entity public information to JEDI's public parameters
// interface.
type WAVEPublicInfo struct {
	eng *engine.Engine
}

// NewWAVEPublicInfo creates and returns a new WAVEPublicInfo. The provided
// engine need not have a perspective.
func NewWAVEPublicInfo(eng *engine.Engine) *WAVEPublicInfo {
	return &WAVEPublicInfo{
		eng: eng,
	}
}

// ParamsForHierarchy accepts as input the multihash for a namespace (as the
// "namespace" argument) and outputs the corresponding WKD-IBE parameters.
func (wpi *WAVEPublicInfo) ParamsForHierarchy(ctx context.Context, namespace []byte) (*wkdibe.Params, error) {
	var err error
	var werr wve.WVE

	/* Get the namespace entity. */

	var nsHash iapi.HashSchemeInstance
	if nsHash = iapi.HashSchemeInstanceFromMultihash(namespace); !nsHash.Supported() {
		return nil, errors.New("could not parse namespace")
	}

	var nsLocation iapi.LocationSchemeInstance
	if nsLocation, werr = eapi.LocationSchemeInstance(nil); werr != nil {
		return nil, werr
	}
	if nsLocation == nil {
		nsLocation = iapi.SI().DefaultLocation(ctx)
	}

	var nsEntity *iapi.Entity
	var nsValidity *engine.Validity
	if nsEntity, nsValidity, err = wpi.eng.LookupEntity(ctx, nsHash, nsLocation); err != nil {
		return nil, err
	}
	if !nsValidity.Valid {
		return nil, errors.New("namespace entity is no longer valid")
	}

	/* Get the WKD-IBE public parameters from the namespace entity. */
	params := new(wkdibe.Params)
	for _, keyring := range nsEntity.Keys {
		wrapped, ok := keyring.(*iapi.EntityKey_OAQUE_BLS12381_S20_Params)
		if ok {
			marshalled := wrapped.SerdesForm.Key.Content.(serdes.EntityParamsOQAUE_BLS12381_s20)
			if params.Unmarshal(marshalled, true, false) {
				return params, nil
			}
		}
	}
	return nil, errors.New("could not find WKD-IBE params in namespace entity")
}

// WAVEKeyStore implements the jedi.KeyStoreReader interface. It lifts a WAVE
// entity's view of the attestation graph to JEDI's key storage interface. The
// (abstract) key store consists of the keys in all attestations decryptable by
// that WAVE entity.
type WAVEKeyStore struct {
	eng *engine.Engine
}

// NewWAVEKeyStore creates and returns a new WAVEKeyStore. The entity whose
// perpsective to use is implicit in the WAVE engine that is passed as an
// argument to this function.
func NewWAVEKeyStore(eng *engine.Engine) *WAVEKeyStore {
	return &WAVEKeyStore{
		eng: eng,
	}
}

// KeyForPattern retrieves a key whose pattern matches the one provided as
// input, within the provided namespace. This function resyncs the graph as
// necessary to query the most up-to-date information.
func (wks *WAVEKeyStore) KeyForPattern(ctx context.Context, namespace []byte, pattern jedi.Pattern) (*wkdibe.Params, *wkdibe.SecretKey, error) {
	var err error
	var dctx *engine.EngineDecryptionContext

	dctx = engine.NewEngineDecryptionContext(wks.eng)
	dctx.AutoLoadPartitionSecrets(true)

	reader := iapi.WR1JEDIKeyStoreReader{WR1JEDIKeyRetriever: dctx}

	synced := false

	var params *wkdibe.Params
	var key *wkdibe.SecretKey
searchforkey:
	if params, key, err = reader.KeyForPattern(ctx, namespace, pattern); err != nil {
		return nil, nil, err
	}
	if key == nil {
		/* If we've already tried resyncing the graph, then give up. */
		if synced {
			return nil, nil, errors.New("could not find suitable key")
		}

		/* If not, resync the graph and try again. */
		if err = wks.eng.ResyncEntireGraph(ctx); err != nil {
			return nil, nil, err
		}
		<-wks.eng.WaitForEmptySyncQueue()
		synced = true
		goto searchforkey
	}

	return params, key, nil
}
