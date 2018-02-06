package iapi

import (
	"context"
	"encoding/asn1"

	"github.com/immesys/wave/serdes"
)

type Entity struct {
	CanonicalForm *serdes.WaveEntity
	VerifyingKey  EntityKeySchemeInstance
	Keys          []EntityKeySchemeInstance
	Revocations   []RevocationScheme
	Extensions    []ExtensionSchemeInstance
}

func (e *Entity) Hash(ctx context.Context, scheme HashScheme) (HashSchemeInstance, error) {
	// e.cachemu.Lock()
	// defer e.cachemu.Unlock()
	// soid := scheme.String()
	// cached, ok := e.CachedHashes[soid]
	// if ok {
	// 	return cached
	// }
	tbhder, err := asn1.Marshal(*e.CanonicalForm)
	if err != nil {
		panic(err)
	}
	rv, err := scheme.Instance(ctx, tbhder)
	return rv, err
}

// func (e *Entity) HashAsExternal() asn1.External {
// 	panic("ni")
// }

type EntitySecrets struct {
	CanonicalForm *serdes.WaveEntitySecret
	Keyring       []EntitySecretKeySchemeInstance
	Entity        *Entity
}

func (e *EntitySecrets) PrimarySigningKey() EntitySecretKeySchemeInstance {
	//spew.Dump(e.Keyring)
	return e.Keyring[0]
}

type Attestation struct {
	//Before any decryption was applied
	CanonicalForm *serdes.WaveAttestation
	//After we decrypted
	DecryptedBody *serdes.AttestationBody
}
