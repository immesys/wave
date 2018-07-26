package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"
	"github.com/ucbrise/starwave/crypto/oaque"

	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

type NameDeclaration struct {
	CanonicalForm    *serdes.WaveNameDeclaration
	DecryptedBody    *serdes.NameDeclarationBody
	Attester         HashSchemeInstance
	AttesterLocation LocationSchemeInstance
	Subject          HashSchemeInstance
	SubjectLocation  LocationSchemeInstance
	Name             string
	Revocations      []RevocationSchemeInstance
	WR1Extra         *WR1Extra
}

func (nd *NameDeclaration) SetCanonicalForm(cf *serdes.WaveNameDeclaration) wve.WVE {
	att := HashSchemeInstanceFor(&cf.TBS.Attester)
	if !att.Supported() {
		return wve.Err(wve.MalformedObject, "unsupported attester hash scheme")
	}
	attloc := LocationSchemeInstanceFor(&cf.TBS.AttesterLocation)
	if !attloc.Supported() {
		return wve.Err(wve.MalformedObject, "unsupported attester location scheme")
	}
	nd.Attester = att
	nd.AttesterLocation = attloc
	//TODO
	//nd.Revocations = []RevocationScheme{}
	nd.CanonicalForm = cf
	return nil
}
func (nd *NameDeclaration) DER() ([]byte, wve.WVE) {
	wo := serdes.WaveWireObject{}
	wo.Content = asn1.NewExternal(*nd.CanonicalForm)
	rv, err := asn1.Marshal(wo.Content)
	if err != nil {
		return nil, wve.Err(wve.MalformedDER, "could not produce DER")
	}
	return rv, nil
}

func (nd *NameDeclaration) Hash(scheme HashScheme) HashSchemeInstance {
	der, err := nd.DER()
	if err != nil {
		panic(err)
	}
	return scheme.Instance(der)
}

func (nd *NameDeclaration) Keccak256() []byte {
	hi := nd.Hash(KECCAK256)
	rv := hi.Value()
	return rv
}
func (nd *NameDeclaration) Keccak256HI() HashSchemeInstance {
	rv := nd.Hash(KECCAK256)
	return rv
}
func (nd *NameDeclaration) ArrayKeccak256() [32]byte {
	rv := [32]byte{}
	copy(rv[:], nd.Keccak256())
	return rv
}

func (nd *NameDeclaration) SetDecryptedBody(db *serdes.NameDeclarationBody) wve.WVE {
	sub := HashSchemeInstanceFor(&db.Subject)
	if !sub.Supported() {
		return wve.Err(wve.MalformedObject, "unsupported subject hash scheme")
	}
	subloc := LocationSchemeInstanceFor(&db.SubjectLocation)
	if !subloc.Supported() {
		return wve.Err(wve.MalformedObject, "unsupported subject location scheme")

	}
	nd.Name = db.Name
	nd.DecryptedBody = db
	nd.Subject = sub
	nd.SubjectLocation = subloc
	if !nd.IsNameValid() {
		return wve.Err(wve.MalformedObject, "name is invalid")
	}
	return nil
}
func (nd *NameDeclaration) Decoded() bool {
	return nd.DecryptedBody != nil
}
func (nd *NameDeclaration) IsNameValid() bool {
	return IsNameDeclarationValid(nd.Name)
}

type Entity struct {
	CanonicalForm *serdes.WaveEntity
	VerifyingKey  EntityKeySchemeInstance
	Keys          []EntityKeySchemeInstance
	Revocations   []RevocationSchemeInstance
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

func (e *EntitySecrets) CommitmentRevocationDetails() (content []byte, loc []LocationSchemeInstance) {
	secret := e.Keyring[0].SecretCanonicalForm().Private.Content.(serdes.EntitySecretEd25519)
	hash := []byte("revocation")
	hash = append(hash, secret...)
	hi := KECCAK256.Instance(hash)

	locs := []LocationSchemeInstance{}
	for _, ro := range e.Entity.CanonicalForm.TBS.Revocations {
		cr, ok := ro.Scheme.Content.(serdes.CommitmentRevocation)
		if !ok {
			continue
		}
		l := LocationSchemeInstanceFor(&cr.Location)
		if l.Supported() {
			locs = append(locs, l)
		}
	}
	return hi.Value(), locs
}
func (e *EntitySecrets) AttestationRevocationDetails(att *Attestation) ([]byte, LocationSchemeInstance, wve.WVE) {
	secret1 := e.Keyring[0].SecretCanonicalForm().Private.Content.(serdes.EntitySecretEd25519)
	hash := []byte("revocation")
	hash = append(hash, secret1...)
	os, ok := att.CanonicalForm.OuterSignature.Content.(serdes.Ed25519OuterSignature)
	if !ok {
		return nil, nil, wve.Err(wve.InvalidParameter, "object does not use WR1 outer signature")
	}
	hash = append(hash, os.VerifyingKey...)
	hi := KECCAK256.Instance(hash)
	hi2 := KECCAK256.Instance(hi.Value())
	for _, ro := range att.CanonicalForm.TBS.Revocations {
		cr, ok := ro.Scheme.Content.(serdes.CommitmentRevocation)
		if !ok {
			continue
		}
		exhi := HashSchemeInstanceFor(&cr.Hash)
		if exhi.MultihashString() != hi2.MultihashString() {
			return nil, nil, wve.Err(wve.InvalidParameter, "attestation was not created by the given entity")
		}
	}
	_, subjloc := att.Subject()
	return hi.Value(), subjloc, nil
}
func (e *EntitySecrets) NameDeclarationRevocationDetails(nd *NameDeclaration) ([]byte, LocationSchemeInstance, wve.WVE) {
	secret1 := e.Keyring[0].SecretCanonicalForm().Private.Content.(serdes.EntitySecretEd25519)

	modified_tbs := nd.CanonicalForm.TBS
	modified_tbs.Revocations = nil

	tbsder, err := asn1.Marshal(modified_tbs)
	if err != nil {
		panic(err)
	}
	hash := []byte("revocation")
	hash = append(hash, secret1...)
	hash = append(hash, tbsder...)
	hi := KECCAK256.Instance(hash)
	return hi.Value(), nd.SubjectLocation, nil
}
func (e *EntitySecrets) PrimarySigningKey() EntitySecretKeySchemeInstance {
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
	//Revocationbs
	Revocations []RevocationSchemeInstance
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
			realk, err := EntitySecretKeySchemeInstanceFor(&kre)
			if err != nil {
				panic(err)
			}
			rv = append(rv, realk.(SlottedSecretKey))
			continue
		}
		kb, ok := ex.Content.(serdes.BN256OAQUEKeyringBundle)
		if ok {
			parts, err := DecodeKeyBundleEntries(kb.Entries)
			if err != nil {
				fmt.Printf("COULD NOT UNMARSHAL KEY BUNDLE\n")
				continue
			}
			//TODO we are not populating the public key nor the canonical form
			// this might come back to bite us later as this is the exact object
			// that gets persisted in WS
			pub := oaque.Params{}
			ok := pub.Unmarshal(kb.Params)
			if !ok {
				fmt.Printf("Bad oaque params\n")
				continue
			}
			for i := 0; i < len(parts); i++ {
				priv := oaque.PrivateKey{}
				ok = priv.Unmarshal(kb.Entries[i].Key)
				if !ok {
					fmt.Printf("COULD NOT UNMARSHAL KEY\n")
					continue
				}

				esk := &EntitySecretKey_OAQUE_BN256_S20{
					SerdesForm: &serdes.EntityKeyringEntry{
						Public: serdes.EntityPublicKey{
							Capabilities: []int{int(CapEncryption)},
						},
					},
					Params:       &pub,
					PrivateKey:   &priv,
					AttributeSet: parts[i],
				}
				//fmt.Printf("KB %2d : %s : %x\n", i, WR1PartitionToString(parts[i]), esk.IdHash())
				rv = append(rv, esk)
			}
		}
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
	n := time.Now()
	//fmt.Printf("now is %v\n", n)
	rv := n.After(v.NotAfter)
	//fmt.Printf("returning att expired %v\n", rv)
	return rv, nil
	//return time.Now().After(v.NotAfter), nil
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
