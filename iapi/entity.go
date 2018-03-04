package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

type PNewEntity struct {
	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil                   *time.Time
	CommitmentRevocationLocation LocationSchemeInstance
}
type RNewEntity struct {
	PublicDER []byte
	SecretDER []byte
}

//Creates a new WR1 entity object and returns the public and secret
//canonical representations
func NewEntity(ctx context.Context, p *PNewEntity) (*RNewEntity, error) {
	en := serdes.WaveEntitySecret{}

	if p.ValidFrom != nil {
		en.Entity.TBS.Validity.NotBefore = *p.ValidFrom
	} else {
		en.Entity.TBS.Validity.NotBefore = time.Now()
	}
	if p.ValidUntil != nil {
		en.Entity.TBS.Validity.NotAfter = *p.ValidUntil
	} else {
		en.Entity.TBS.Validity.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	}

	//add the WR1 keys
	kr := serdes.EntityKeyring{}

	//Ed25519 attest/certify
	ed25519KE, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapAttestation, CapCertification)
	if err != nil {
		return nil, err
	}
	cf, err := ed25519KE.SecretCanonicalForm(context.Background())
	if err != nil {
		return nil, err
	}
	kr.Keys = append(kr.Keys, *cf)

	//Ed25519 message signing
	{
		ed25519KE, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapSigning)
		if err != nil {
			return nil, err
		}
		cf, err := ed25519KE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}

	//Curve25519
	{
		curve25519KE, err := NewEntityKeySchemeInstance(serdes.EntityCurve25519OID, CapEncryption)
		if err != nil {
			return nil, err
		}
		cf, err := curve25519KE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}
	// IBE
	{
		ibeKE, err := NewEntityKeySchemeInstance(serdes.EntityIBE_BN256_ParamsOID, CapEncryption)
		if err != nil {
			return nil, err
		}
		cf, err := ibeKE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}
	// OAQUE
	{
		oaqueKE, err := NewEntityKeySchemeInstance(serdes.EntityOAQUE_BN256_S20_ParamsOID, CapEncryption)
		if err != nil {
			return nil, err
		}
		cf, err := oaqueKE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}

	//Put the keyring into the secret entity object
	en.Keyring = asn1.NewExternal(kr)

	//For all our secret keys, put the public ones in the public entity
	for _, ke := range kr.Keys[1:] {
		en.Entity.TBS.Keys = append(en.Entity.TBS.Keys, ke.Public)
	}
	//Put the canonical certification key in
	en.Entity.TBS.VerifyingKey = kr.Keys[0].Public

	//Serialize TBS and sign it
	der, err := asn1.Marshal(en.Entity.TBS)
	if err != nil {
		return nil, err
	}
	en.Entity.Signature, err = ed25519KE.SignCertify(context.Background(), der)
	if err != nil {
		return nil, err
	}

	//Serialize wrapped public part
	publicEntity := serdes.WaveWireObject{}
	publicEntity.Content = asn1.NewExternal(en.Entity)
	publicDER, err := asn1.Marshal(publicEntity.Content)
	if err != nil {
		return nil, err
	}
	//Serialize secret
	secretEntity := serdes.WaveWireObject{}
	secretEntity.Content = asn1.NewExternal(en)
	secretDER, err := asn1.Marshal(secretEntity.Content)
	if err != nil {
		return nil, err
	}

	//spew.Dump(secretEntity)
	return &RNewEntity{
		PublicDER: publicDER,
		SecretDER: secretDER,
	}, nil
}

type PParseEntity struct {
	DER []byte
}
type RParseEntity struct {
	Entity *Entity
}

func parseEntityFromObject(ctx context.Context, en *serdes.WaveEntity) (*Entity, error) {

	//Ok we have an entity object, lets check the signature
	ks, err := EntityKeySchemeInstanceFor(&en.TBS.VerifyingKey)
	if err != nil {
		return nil, err
	}
	if !ks.Supported() {
		return nil, fmt.Errorf("entity uses unsupported key scheme")
	}

	err = ks.VerifyCertify(ctx, en.TBS.Raw, en.Signature)
	if err != nil {
		return nil, fmt.Errorf("entity signature check failed: %v", err)
	}

	//Entity appears ok, lets unpack it further
	rv := &Entity{}
	rv.CanonicalForm = en
	rv.VerifyingKey = ks
	//TODO
	//rv.revocations
	//TODO
	//rv.extensions

	for _, key := range en.TBS.Keys {
		lkey := key
		ks, err := EntityKeySchemeInstanceFor(&lkey)
		if err != nil {
			panic(err)
		}
		rv.Keys = append(rv.Keys, ks)
	}
	return rv, nil
}
func ParseEntity(ctx context.Context, p *PParseEntity) (*RParseEntity, error) {
	wo := serdes.WaveWireObject{}
	trailing, err := asn1.Unmarshal(p.DER, &wo.Content)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %v", err)
	}
	if len(trailing) != 0 {
		return nil, fmt.Errorf("could not decode: trailing content")
	}
	en, ok := wo.Content.Content.(serdes.WaveEntity)
	if !ok {
		return nil, fmt.Errorf("object not an entity")
	}
	rv, err := parseEntityFromObject(ctx, &en)
	if err != nil {
		return nil, err
	}
	return &RParseEntity{
		Entity: rv,
	}, nil
}

type PParseEntitySecrets struct {
	DER        []byte
	Passphrase *string
}
type RParseEntitySecrets struct {
	EntitySecrets *EntitySecrets
}

func ParseEntitySecrets(ctx context.Context, p *PParseEntitySecrets) (*RParseEntitySecrets, error) {
	wo := serdes.WaveWireObject{}
	trailing, err := asn1.Unmarshal(p.DER, &wo.Content)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %v", err)
	}
	if len(trailing) != 0 {
		return nil, fmt.Errorf("could not decode: trailing content")
	}
	es, ok := wo.Content.Content.(serdes.WaveEntitySecret)
	if !ok {
		return nil, fmt.Errorf("object not an entity")
	}
	en, err := parseEntityFromObject(ctx, &es.Entity)
	if err != nil {
		return nil, err
	}
	krscheme, err := EntityKeyringSchemeInstanceFor(es.Keyring)
	if err != nil {
		return nil, err
	}
	if !krscheme.Supported() {
		return nil, fmt.Errorf("keyring scheme is unsupported")
	}
	//Try
	if _, ok := krscheme.(*AESKeyring); ok && p.Passphrase == nil {
		return nil, fmt.Errorf("passphrase required")
	}
	keyring, err := krscheme.DecryptKeyring(context.Background(), p.Passphrase)
	if err != nil {
		return nil, err
	}
	rv := EntitySecrets{
		Entity: en,
	}
	for _, key := range keyring.Keys {
		lkey := key
		eks, err := EntitySecretKeySchemeInstanceFor(&lkey)
		if err != nil {
			return nil, err
		}
		rv.Keyring = append(rv.Keyring, eks)
	}

	return &RParseEntitySecrets{
		EntitySecrets: &rv,
	}, nil
}

func NewParsedEntitySecrets(ctx context.Context, p *PNewEntity) (*RParseEntitySecrets, error) {
	rn, err := NewEntity(ctx, p)
	if err != nil {
		return nil, err
	}
	rv, err := ParseEntitySecrets(ctx, &PParseEntitySecrets{
		DER: rn.SecretDER,
	})
	return rv, err
}
