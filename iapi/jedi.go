package iapi

import (
	"context"
	"errors"

	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
	"github.com/ucbrise/jedi-protocol-go"
)

// WR1JEDIKeyRetriever describes an object that can retrieve JEDI keys from an
// entity's local storage, among those used in WR1.
type WR1JEDIKeyRetriever interface {
	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, delegable bool, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
}

// WR1JEDIKeyStoreReader lifts a WR1JEDIKeyRetriever to the jedi.KeyStoreReader
// interface.
type WR1JEDIKeyStoreReader struct {
	WR1JEDIKeyRetriever
}

// KeyForPattern retrieves a key whose pattern matches the one provided as
// input, within the provided namespace.
func (jksr *WR1JEDIKeyStoreReader) KeyForPattern(ctx context.Context, namespace []byte, pattern jedi.Pattern) (*wkdibe.Params, *wkdibe.SecretKey, error) {
	var nsHash HashSchemeInstance
	if nsHash = HashSchemeInstanceFromMultihash(namespace); !nsHash.Supported() {
		return nil, nil, errors.New("could not parse namespace")
	}

	var params *wkdibe.Params
	var key *wkdibe.SecretKey
	var err error
	if err = jksr.WR1OAQUEKeysForContent(ctx, nsHash, false, pattern, func(k SlottedSecretKey) bool {
		wrapped, ok := k.(*EntitySecretKey_OAQUE_BLS12381_S20)
		if ok {
			params = wrapped.Params
			key = wrapped.PrivateKey
			return false
		}
		return false
	}); err != nil {
		return nil, nil, err
	}
	return params, key, nil
}
