package iapi

import (
	"context"
	"encoding/asn1"
	"fmt"
	"time"

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
func (e *Entity) Expired() bool {
	return time.Now().After(e.CanonicalForm.TBS.Validity.NotAfter)
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
func (e *EntitySecrets) WR1LabelKey(ctx context.Context, namespace []byte) (EntitySecretKeySchemeInstance, error) {
	for _, kr := range e.Keyring {
		master, ok := kr.(*EntitySecretKey_IBE_Master_BN256)
		if ok {
			return master.GenerateChildSecretKey(ctx, namespace)
		}
	}
	return nil, fmt.Errorf("no WR1 label key found")
}
func (e *EntitySecrets) WR1BodyKey(ctx context.Context, slots [][]byte) (SlottedSecretKey, error) {
	if len(slots) != 20 {
		return nil, fmt.Errorf("WR1 uses 20 slots")
	}
	for _, kr := range e.Keyring {
		master, ok := kr.(*EntitySecretKey_OAQUE_BN256_S20_Master)
		if ok {
			rv, e := master.GenerateChildSecretKey(ctx, slots)
			return rv.(*EntitySecretKey_OAQUE_BN256_S20), e
		}
	}
	return nil, fmt.Errorf("no WR1 body key found")
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

func (e *Attestation) Keccak256() []byte {
	hi, err := e.Hash(context.Background(), KECCAK256)
	if err != nil {
		panic(err)
	}
	rv := hi.Value()
	return rv
}
func (e *Attestation) Subject() (HashSchemeInstance, LocationSchemeInstance) {
	rv := HashSchemeInstanceFor(&e.CanonicalForm.TBS.Subject)
	rvloc := LocationSchemeInstanceFor(&e.CanonicalForm.TBS.SubjectLocation)
	return rv, rvloc
}
func (e *Attestation) Attester() (HashSchemeInstance, LocationSchemeInstance, error) {
	if e.DecryptedBody == nil {
		return nil, nil, fmt.Errorf("Attestation is not decrypted")
	}
	rv := HashSchemeInstanceFor(&e.DecryptedBody.VerifierBody.Attester)
	rvloc := LocationSchemeInstanceFor(&e.DecryptedBody.VerifierBody.AttesterLocation)
	return rv, rvloc, nil
}
func (e *Attestation) Expired() (bool, error) {
	if e.DecryptedBody == nil {
		return true, fmt.Errorf("Attestation is not decrypted")
	}
	v := e.DecryptedBody.VerifierBody.Validity
	return time.Now().After(v.NotAfter), nil
}
func (e *Attestation) Keccak256HI() HashSchemeInstance {
	hi, err := e.Hash(context.Background(), KECCAK256)
	if err != nil {
		panic(err)
	}
	return hi
}
func (e *Attestation) ArrayKeccak256() [32]byte {
	rv := [32]byte{}
	copy(rv[:], e.Keccak256())
	return rv
}
func (e *Attestation) WR1SlottedKeys() ([]SlottedSecretKey, error) {
	panic("ni")
}
func (e *Attestation) WR1DomainVisibilityKeys() ([]EntitySecretKeySchemeInstance, error) {
	panic("ni")
}
func (e *Attestation) DER() ([]byte, error) {
	tbhder, err := asn1.Marshal(*e.CanonicalForm)
	return tbhder, err
}
