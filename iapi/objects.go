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
	rv, err := scheme.Instance(tbhder)
	return rv, err
}

func (e *Entity) DER() ([]byte, error) {
	tbhder, err := asn1.Marshal(*e.CanonicalForm)
	return tbhder, err
}

func (e *Entity) Keccak256() []byte {
	hi, err := e.Hash(context.Background(), KECCAK256)
	if err != nil {
		panic(err)
	}
	rv := hi.Value()
	return rv
}
func (e *Entity) Keccak256HI() HashSchemeInstance {
	rv, err := e.Hash(context.Background(), KECCAK256)
	if err != nil {
		panic(err)
	}
	return rv
}
func (e *Entity) ArrayKeccak256() [32]byte {
	rv := [32]byte{}
	copy(rv[:], e.Keccak256())
	return rv
}

func ToArr32(b []byte) [32]byte {
	rv := [32]byte{}
	copy(rv[:], b)
	return rv
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
	//If the dot is labelled but not fully decrypted, this will be present
	//but the decrypted body will be null
	WR1Partition [][]byte
}

func (e *Attestation) Hash(ctx context.Context, scheme HashScheme) (HashSchemeInstance, error) {
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
	rv, err := scheme.Instance(tbhder)
	return rv, err
}

func (e *Attestation) Keccack256() []byte {
	hi, err := e.Hash(context.Background(), KECCAK256)
	if err != nil {
		panic(err)
	}
	rv := hi.Value()
	return rv
}

func (e *Attestation) DER() ([]byte, error) {
	tbhder, err := asn1.Marshal(*e.CanonicalForm)
	return tbhder, err
}
