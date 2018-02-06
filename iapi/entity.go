package iapi

import (
	"context"
	"fmt"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

type PNewEntity struct {
	Contact *string
	Comment *string
	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil *time.Time
}
type RNewEntity struct {
	PublicDER []byte
	SecretDER []byte
}

//Creates a new WR1 entity object and returns the public and secret
//canonical representations
func NewEntity(ctx context.Context, p *PNewEntity) (*RNewEntity, error) {
	en := serdes.WaveEntitySecret{}

	if p.Comment != nil {
		en.Entity.TBS.Comment = *p.Comment
	}
	if p.Contact != nil {
		en.Entity.TBS.Contact = *p.Contact
	}
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

	//Ed25519

	ed25519KE, err := NewEntityKeyScheme(serdes.EntityEd25519OID)
	if err != nil {
		return nil, err
	}
	cf, err := ed25519KE.SecretCanonicalForm(context.Background())
	if err != nil {
		return nil, err
	}
	kr.Keys = append(kr.Keys, *cf)

	//
	// publicEd25519, privateEd25519, err := ed25519.GenerateKey(rand.Reader)
	// if err != nil {
	// 	return nil, err
	// }
	// ke := serdes.EntityKeyringEntry{
	// 	Public: serdes.EntityPublicKey{
	// 		Capabilities: []int{int(CapAttestation), int(CapCertification)},
	// 		Key:          asn1.NewExternal(serdes.EntityPublicEd25519(publicEd25519)),
	// 	},
	// 	Private: asn1.NewExternal(serdes.EntitySecretEd25519(privateEd25519)),
	// }
	// kr.Keys = append(kr.Keys, ke)

	//Curve25519
	{
		curve25519KE, err := NewEntityKeyScheme(serdes.EntityCurve25519OID)
		if err != nil {
			return nil, err
		}
		cf, err := curve25519KE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}
	//
	// {
	// 	var secret [32]byte
	// 	_, err = rand.Read(secret[:])
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	var public [32]byte
	// 	curve25519.ScalarBaseMult(&public, &secret)
	// 	ke := serdes.EntityKeyringEntry{
	// 		Public: serdes.EntityPublicKey{
	// 			Capabilities: []int{int(CapEncryption)},
	// 			Key:          asn1.NewExternal(serdes.EntityPublicCurve25519(public[:])),
	// 		},
	// 		Private: asn1.NewExternal(serdes.EntitySecretCurve25519(secret[:])),
	// 	}
	// 	kr.Keys = append(kr.Keys, ke)
	// }
	{
		ibeKE, err := NewEntityKeyScheme(serdes.EntityIBE_BN256_ParamsOID)
		if err != nil {
			return nil, err
		}
		cf, err := ibeKE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}
	//
	// //IBE
	// {
	// 	params, master := ibe.Setup(rand.Reader)
	// 	paramsblob, err := params.MarshalBinary()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	masterblob, err := master.MarshalBinary()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ke := serdes.EntityKeyringEntry{
	// 		Public: serdes.EntityPublicKey{
	// 			Capabilities: []int{int(CapEncryption)},
	// 			Key:          asn1.NewExternal(serdes.EntityParamsIBE_BN256(paramsblob)),
	// 		},
	// 		Private: asn1.NewExternal(serdes.EntitySecretMasterIBE_BN256(masterblob)),
	// 	}
	// 	kr.Keys = append(kr.Keys, ke)
	// }
	{
		oaqueKE, err := NewEntityKeyScheme(serdes.EntityOAQUE_BN256_S20_ParamsOID)
		if err != nil {
			return nil, err
		}
		cf, err := oaqueKE.SecretCanonicalForm(context.Background())
		if err != nil {
			return nil, err
		}
		kr.Keys = append(kr.Keys, *cf)
	}
	//
	// //OAQUE
	// {
	// 	params, master, err := crypto.GenerateOAQUEKeys()
	// 	paramsblob := params.Marshal()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	masterblob := master.Marshal()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ke := serdes.EntityKeyringEntry{
	// 		Public: serdes.EntityPublicKey{
	// 			Capabilities: []int{int(CapEncryption), int(CapAuthorization)},
	// 			Key:          asn1.NewExternal(serdes.EntityParamsOQAUE_BN256_s20(paramsblob)),
	// 		},
	// 		Private: asn1.NewExternal(serdes.EntitySecretMasterOQAUE_BN256_s20(masterblob)),
	// 	}
	// 	kr.Keys = append(kr.Keys, ke)
	// }
	//Put the keyring into the secret entity object
	en.Keyring = asn1.NewExternal(kr)

	//For all our secret keys, put the public ones in the public entity
	for _, ke := range kr.Keys[1:] {
		en.Entity.TBS.Keys = append(en.Entity.TBS.Keys, ke.Public)
	}
	//Put the canonical certification key in
	en.Entity.TBS.VerifyingKey = kr.Keys[0].Public

	//TODO commitmentrevocation

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

	//Ok we have an entity object, lets check the signature
	ks := EntityKeySchemeFor(&en.TBS.VerifyingKey)
	if !ks.Supported() {
		return nil, fmt.Errorf("entity uses unsupported key scheme")
	}

	err = ks.VerifyCertify(ctx, en.TBS.Raw, en.Signature)
	if err != nil {
		return nil, fmt.Errorf("entity signature check failed: %v", err)
	}

	//Entity appears ok, lets unpack it further
	rv := &Entity{}
	rv.canonicalForm = &en
	rv.verifyingKey = ks
	//TODO
	//rv.revocations
	//TODO
	//rv.extensions

	for _, key := range en.TBS.Keys {
		rv.keys = append(rv.keys, EntityKeySchemeFor(&key))
	}

	return &RParseEntity{
		Entity: rv,
	}, nil
}
