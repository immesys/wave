package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"

	"github.com/immesys/wave/serdes"
)

type Entity struct {
	CanonicalForm *serdes.WaveEntity
	VerifyingKey  EntityKeySchemeInstance
	Keys          []EntityKeySchemeInstance
	Revocations   []RevocationScheme
	Extensions    []ExtensionSchemeInstance
}

func (e *Entity) Hash(scheme HashScheme) HashSchemeInstance {
	der, err := e.DER()
	if err != nil {
		panic(err)
	}
	return scheme.Instance(der)
}

func (e *Entity) DER() ([]byte, error) {
	wo := serdes.WaveWireObject{}
	wo.Content.OID = serdes.EntityOID
	wo.Content.Content = *e.CanonicalForm
	tbhder, err := asn1.Marshal(wo.Content)
	return tbhder, err
}

func (e *Entity) WR1_DomainVisiblityParams() (EntityKeySchemeInstance, error) {
	for _, kr := range e.Keys {
		params, ok := kr.(*EntityKey_IBE_Params_BN256)
		if ok {
			return params, nil
		}
	}
	return nil, fmt.Errorf("no WR1 IBE params found")
}
func (e *Entity) WR1_BodyParams() (EntityKeySchemeInstance, error) {
	for _, kr := range e.Keys {
		params, ok := kr.(*EntityKey_OAQUE_BN256_S20_Params)
		if ok {
			return params, nil
		}
	}
	return nil, fmt.Errorf("no WR1 OAQUE params found")
}
func (e *Entity) WR1_DirectEncryptionKey() (EntityKeySchemeInstance, error) {
	//curve25519
	for _, kr := range e.Keys {
		pk, ok := kr.(*EntityKey_Curve25519)
		if ok {
			return pk, nil
		}
	}
	return nil, fmt.Errorf("no WR1 Curve25519 key found")
}
func (e *Entity) Keccak256() []byte {
	hi := e.Hash(KECCAK256)
	rv := hi.Value()
	return rv
}
func (e *Entity) Keccak256HI() HashSchemeInstance {
	rv := e.Hash(KECCAK256)
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
func (e *EntitySecrets) WR1DirectDecryptionKey(ctx context.Context) (EntitySecretKeySchemeInstance, error) {
	for _, kr := range e.Keyring {
		cv, ok := kr.(*EntitySecretKey_Curve25519)
		if ok {
			return cv, nil
		}
	}
	return nil, fmt.Errorf("no WR1 direct encryption key found")
}

type Attestation struct {
	//Before any decryption was applied
	CanonicalForm *serdes.WaveAttestation
	//After we decrypted
	DecryptedBody *serdes.AttestationBody
	//Extra information obtained if this is a WR1 dot
	WR1Extra *WR1Extra
	//Extra information obtained if this is a PSK dot
	PSKExtra *PSKExtra
}

func (e *Attestation) Hash(scheme HashScheme) HashSchemeInstance {
	// e.cachemu.Lock()
	// defer e.cachemu.Unlock()
	// soid := scheme.String()
	// cached, ok := e.CachedHashes[soid]
	// if ok {
	// 	return cached
	// }
	tbhder, err := e.DER()
	if err != nil {
		panic(err)
	}
	rv := scheme.Instance(tbhder)
	return rv
}

func (e *Attestation) WR1SecretSlottedKeys() []SlottedSecretKey {
	rv := []SlottedSecretKey{}
	for _, ex := range e.DecryptedBody.ProverPolicyAddendums {
		var kre serdes.EntityKeyringEntry
		k, ok := ex.Content.(serdes.WR1PartitionKey_OAQUE_BN256_s20)
		if ok {
			kre = serdes.EntityKeyringEntry(k)
		} else {
			k, ok := ex.Content.(serdes.WR1EncryptionKey_OAQUE_BN256_s20)
			if ok {
				kre = serdes.EntityKeyringEntry(k)
			} else {
				continue
			}
		}
		realk, err := EntitySecretKeySchemeInstanceFor(&kre)
		if err != nil {
			panic(err)
		}
		rv = append(rv, realk.(SlottedSecretKey))
	}
	return rv
}
func (e *Attestation) Keccak256() []byte {
	hi := e.Hash(KECCAK256)
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
	hi := e.Hash(KECCAK256)
	return hi
}
func (e *Attestation) ArrayKeccak256() [32]byte {
	rv := [32]byte{}
	copy(rv[:], e.Keccak256())
	return rv
}
func (e *Attestation) WR1DomainVisibilityKeys() []EntitySecretKeySchemeInstance {
	rv := []EntitySecretKeySchemeInstance{}
	for _, ex := range e.DecryptedBody.ProverPolicyAddendums {
		k, ok := ex.Content.(serdes.WR1DomainVisibilityKey_IBE_BN256)
		if ok {
			kre := serdes.EntityKeyringEntry(k)
			realk, err := EntitySecretKeySchemeInstanceFor(&kre)
			if err != nil {
				panic(err)
			}
			rv = append(rv, realk)
		}
	}
	return rv
}
func (e *Attestation) DER() ([]byte, error) {
	wo := serdes.WaveWireObject{}
	wo.Content.OID = serdes.AttestationOID
	wo.Content.Content = *e.CanonicalForm
	tbhder, err := asn1.Marshal(wo.Content)
	return tbhder, err
}
