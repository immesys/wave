package iapi

import (
	"context"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

type PNewEntity struct {
	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil                   *time.Time
	CommitmentRevocationLocation LocationSchemeInstance
	Passphrase                   *string
}
type RNewEntity struct {
	PublicDER []byte
	SecretDER []byte
}

//Creates a new WR1 entity object and returns the public and secret
//canonical representations
func NewEntity(ctx context.Context, p *PNewEntity) (*RNewEntity, wve.WVE) {
	en := serdes.WaveEntitySecret{}
//    if p.CommitmentRevocationLocation == nil {
//        return nil, wve.Err(wve.InvalidParameter, "missing revocation location parameter")
//    }
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
	ed25519KE, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapCertification, CapAttestation)
	if err != nil {
		panic(err)
	}
	cf := ed25519KE.SecretCanonicalForm()
	kr.Keys = append(kr.Keys, *cf)
	rsecret := cf.Private.Content.(serdes.EntitySecretEd25519)

	//Ed25519 message signing
	{
		ed25519KE, err := NewEntityKeySchemeInstance(serdes.EntityEd25519OID, CapSigning)
		if err != nil {
			panic(err)
		}
		cf := ed25519KE.SecretCanonicalForm()
		kr.Keys = append(kr.Keys, *cf)
	}

	//Curve25519
	{
		curve25519KE, err := NewEntityKeySchemeInstance(serdes.EntityCurve25519OID, CapEncryption)
		if err != nil {
			panic(err)
		}
		cf := curve25519KE.SecretCanonicalForm()
		kr.Keys = append(kr.Keys, *cf)
	}
	// IBE
	{
		ibeKE, err := NewEntityKeySchemeInstance(serdes.EntityIBE_BN256_ParamsOID, CapEncryption)
		if err != nil {
			panic(err)
		}
		cf := ibeKE.SecretCanonicalForm()
		kr.Keys = append(kr.Keys, *cf)
	}
	// OAQUE
	{
		oaqueKE, err := NewEntityKeySchemeInstance(serdes.EntityOAQUE_BN256_S20_ParamsOID, CapEncryption)
		if err != nil {
			panic(err)
		}
		cf := oaqueKE.SecretCanonicalForm()
		kr.Keys = append(kr.Keys, *cf)
	}

	if p.Passphrase == nil {
		//Put the keyring into the secret entity object
		en.Keyring = asn1.NewExternal(kr)
	} else {
		//Encrypt the keyring
		krs, err := NewEntityKeyringSchemeInstance(serdes.KeyringAES128_GCM_PBKDF2OID)
		if err != nil {
			panic(err)
		}
		ex, err := krs.EncryptKeyring(context.Background(), &kr, *p.Passphrase)
		if err != nil {
			panic(err)
		}
		en.Keyring = *ex
	}

	//For all our secret keys, put the public ones in the public entity
	for _, ke := range kr.Keys[1:] {
		en.Entity.TBS.Keys = append(en.Entity.TBS.Keys, ke.Public)
	}
	//Put the canonical certification key in
	en.Entity.TBS.VerifyingKey = kr.Keys[0].Public

    if (p.CommitmentRevocationLocation != nil ) {
	ro := NewCommitmentRevocationSchemeInstance(p.CommitmentRevocationLocation, true, rsecret)
	en.Entity.TBS.Revocations = append(en.Entity.TBS.Revocations, ro.CanonicalForm())
    }
	//Serialize TBS and sign it
	der, err := asn1.Marshal(en.Entity.TBS)
	if err != nil {
		panic(err)
	}
	en.Entity.Signature, err = ed25519KE.SignCertify(context.Background(), der)
	if err != nil {
		panic(err)
	}

	//Serialize wrapped public part
	publicEntity := serdes.WaveWireObject{}
	publicEntity.Content = asn1.NewExternal(en.Entity)
	publicDER, err := asn1.Marshal(publicEntity.Content)
	if err != nil {
		panic(err)
	}
	//Serialize secret
	secretEntity := serdes.WaveWireObject{}
	secretEntity.Content = asn1.NewExternal(en)
	secretDER, err := asn1.Marshal(secretEntity.Content)
	if err != nil {
		panic(err)
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

func parseEntityFromObject(ctx context.Context, en *serdes.WaveEntity) (*Entity, wve.WVE) {

	//Ok we have an entity object, lets check the signature
	ks, err := EntityKeySchemeInstanceFor(&en.TBS.VerifyingKey)
	if err != nil {
		return nil, wve.Err(wve.UnsupportedKeyScheme, "malformed entity verifying key")
	}
	if !ks.Supported() {
		return nil, wve.Err(wve.UnsupportedKeyScheme, "entity uses unsupported key scheme")
	}

	err = ks.VerifyCertify(ctx, en.TBS.Raw, en.Signature)
	if err != nil {
		return nil, wve.Err(wve.InvalidSignature, "entity signature is incorrect")
	}

	//Entity appears ok, lets unpack it further
	rv := &Entity{}
	rv.CanonicalForm = en
	rv.VerifyingKey = ks

	for _, ro := range en.TBS.Revocations {
		sch := RevocationSchemeInstanceFor(&ro)
		rv.Revocations = append(rv.Revocations, sch)
	}

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
func ParseEntity(ctx context.Context, p *PParseEntity) (*RParseEntity, wve.WVE) {
	wo := serdes.WaveWireObject{}
	trailing, uerr := asn1.Unmarshal(p.DER, &wo.Content)
	if uerr != nil {
		return nil, wve.ErrW(wve.MalformedDER, "could not decode entity", uerr)
	}
	if len(trailing) != 0 {
		return nil, wve.Err(wve.MalformedDER, "could not decode entity: trailing bytes")
	}
	en, ok := wo.Content.Content.(serdes.WaveEntity)
	if !ok {
		//First try check, maybe this is an entity secret
		es, ok := wo.Content.Content.(serdes.WaveEntitySecret)
		if !ok {
			return nil, wve.Err(wve.UnexpectedObject, "object is not a wave entity")
		}
		en = es.Entity
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
	Entity        *Entity
	EntitySecrets *EntitySecrets
}

func ParseEntitySecrets(ctx context.Context, p *PParseEntitySecrets) (*RParseEntitySecrets, wve.WVE) {
	wo := serdes.WaveWireObject{}

	trailing, uerr := asn1.Unmarshal(p.DER, &wo.Content)
	if uerr != nil {
		return nil, wve.ErrW(wve.MalformedDER, "could not decode", uerr)
	}
	if len(trailing) != 0 {
		return nil, wve.Err(wve.MalformedDER, "could not decode: trailing bytes")
	}
	es, ok := wo.Content.Content.(serdes.WaveEntitySecret)
	if !ok {
		return nil, wve.Err(wve.UnexpectedObject, "object is not a wave entity secret")
	}
	en, err := parseEntityFromObject(ctx, &es.Entity)
	if err != nil {
		return nil, err
	}
	krscheme, uerr := EntityKeyringSchemeInstanceFor(es.Keyring)
	if uerr != nil {
		return &RParseEntitySecrets{
			Entity: en,
		}, wve.ErrW(wve.UnsupportedKeyScheme, "keyring scheme is malformed", uerr)
	}
	if !krscheme.Supported() {
		return &RParseEntitySecrets{
			Entity: en,
		}, wve.Err(wve.UnsupportedKeyScheme, "keyring scheme is unsupported")
	}
	//Try
	if _, ok := krscheme.(*AESKeyring); ok && p.Passphrase == nil {
		return &RParseEntitySecrets{
			Entity: en,
		}, wve.Err(wve.PassphraseRequired, "passphrase required")
	}
	keyring, uerr := krscheme.DecryptKeyring(context.Background(), p.Passphrase)
	if uerr != nil {
		return &RParseEntitySecrets{
			Entity: en,
		}, wve.ErrW(wve.KeyringDecryptFailed, "could not decrypt entity secrets", uerr)
	}
	rv := EntitySecrets{
		Entity: en,
	}
	for _, key := range keyring.Keys {
		lkey := key
		eks, uerr := EntitySecretKeySchemeInstanceFor(&lkey)
		if uerr != nil {
			return &RParseEntitySecrets{
				Entity: en,
			}, wve.Err(wve.KeyringDecryptFailed, "keyring contains unsupported keys")
		}
		if !eks.Supported() {
			return &RParseEntitySecrets{
				Entity: en,
			}, wve.Err(wve.KeyringDecryptFailed, "keyring contains unsupported keys")
		}
		rv.Keyring = append(rv.Keyring, eks)
	}

	// Test revocation matches
	// {
	// 	content, _ := rv.CommitmentRevocationDetails()
	// 	hi := KECCAK256.Instance(content)
	// 	expectedHash := HashSchemeInstanceFor(&rv.Entity.Revocations[0].(*CommitmentRevocationSchemeInstance).CRBody.Hash)
	// 	if hi.MultihashString() != expectedHash.MultihashString() {
	// 		panic("revocation mismatch")
	// 	} else {
	// 		fmt.Printf("revocation ok\n")
	// 	}
	// }
	return &RParseEntitySecrets{
		Entity:        en,
		EntitySecrets: &rv,
	}, nil
}

func NewParsedEntitySecrets(ctx context.Context, p *PNewEntity) (*RParseEntitySecrets, wve.WVE) {
	rn, err := NewEntity(ctx, p)
	if err != nil {
		return nil, err
	}
	rv, err := ParseEntitySecrets(ctx, &PParseEntitySecrets{
		DER: rn.SecretDER,
	})
	return rv, err
}
