package iapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

func IsNameDeclarationValid(s string) bool {
	ok, err := regexp.MatchString("^[a-z0-9_-]{1,63}$", s)
	if err != nil {
		panic(err)
	}
	return ok
}

type PCreateNameDeclaration struct {
	Attester         *EntitySecrets
	AttesterLocation LocationSchemeInstance
	Subject          *Entity
	SubjectLocation  LocationSchemeInstance
	Name             string

	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+5 years
	ValidUntil *time.Time

	//If present, an encrypted declaration will be made
	Namespace         *Entity
	NamespaceLocation LocationSchemeInstance
	Partition         [][]byte

	//TODO
	//revocationlocation
}
type RCreateNameDeclaration struct {
	NameDeclaration *NameDeclaration
	DER             []byte
}

func CreateNameDeclaration(ctx context.Context, p *PCreateNameDeclaration) (*RCreateNameDeclaration, wve.WVE) {
	if p.Namespace != nil {
		if p.NamespaceLocation == nil || p.Partition == nil {
			return nil, wve.Err(wve.InvalidParameter, "namespace, nsloc and partition must be specified together")
		}
		if len(p.Partition) > 20 {
			return nil, wve.Err(wve.InvalidParameter, "partition must be <=20 elements")
		}
	}
	if !IsNameDeclarationValid(p.Name) {
		return nil, wve.Err(wve.InvalidParameter, "names must match [a-z0-9_-]{1,63}")
	}
	subcf := p.Subject.Keccak256HI().CanonicalForm()
	subloc := p.SubjectLocation.CanonicalForm()
	body := serdes.NameDeclarationBody{}
	body.Name = p.Name
	body.Subject = *subcf
	body.SubjectLocation = *subloc

	if p.ValidFrom != nil {
		body.Validity.NotBefore = *p.ValidFrom
	} else {
		body.Validity.NotBefore = time.Now()
	}
	if p.ValidUntil != nil {
		body.Validity.NotAfter = *p.ValidUntil
	} else {
		body.Validity.NotAfter = time.Now().Add(3 * 365 * 24 * time.Hour)
	}
	if body.Validity.NotBefore.After(body.Validity.NotAfter) {
		return nil, wve.Err(wve.InvalidParameter, "invalid validity times")
	}
	//Body is complete. Now encode and encrypt it
	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		panic(err)
	}
	attcf := p.Attester.Entity.Keccak256HI().CanonicalForm()
	attlocf := p.AttesterLocation.CanonicalForm()
	outer := serdes.WaveNameDeclaration{}
	outer.TBS.Attester = *attcf
	outer.TBS.AttesterLocation = *attlocf
	if p.Namespace == nil {
		outer.TBS.Body = bodyDER
		outer.TBS.Keys = append(outer.TBS.Keys, asn1.NewExternal(serdes.NameDeclarationKeyNone{}))

	} else {
		expandedPartition, uerr := CalculateWR1Partition(body.Validity.NotBefore,
			body.Validity.NotAfter,
			p.Partition)
		if uerr != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "could not form partition", uerr)
		}

		nscf := p.Namespace.Keccak256HI().CanonicalForm()
		nsloc := p.NamespaceLocation.CanonicalForm()
		wr1key := serdes.NameDeclarationKeyWR1{}
		wr1key.Namespace = *nscf
		wr1key.NamespaceLocation = *nsloc

		aesk := make([]byte, 16+12)
		rand.Read(aesk)
		bodyciphertext := aesGCMEncrypt(aesk[:16], bodyDER, aesk[16:])
		outer.TBS.Body = bodyciphertext
		//Now create the OAQUE key

		oaqueparams, err := p.Namespace.WR1_BodyParams()
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity has invalid WR1 params", err)
		}
		ck, err := oaqueparams.GenerateChildKey(ctx, expandedPartition)
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity has invalid WR1 params", err)
		}
		bodykeyciphertext, err := ck.EncryptMessage(ctx, aesk)
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity has invalid WR1 params", err)
		}
		// ^^ oaque encrypted aesk

		ndwr1keyenv := serdes.NameDeclarationWR1Envelope{
			Partition: expandedPartition,
			BodyKey:   bodykeyciphertext,
		}
		serenv, err := asn1.Marshal(ndwr1keyenv)
		if err != nil {
			panic(err)
		}

		envelopeAESK := make([]byte, 16+12)
		rand.Read(envelopeAESK)
		serenvCiphertext := aesGCMEncrypt(envelopeAESK[:16], serenv, envelopeAESK[16:])
		wr1key.Envelope = serenvCiphertext

		//Encrypt envelope key with IBE
		ibeparams, err := p.Namespace.WR1_DomainVisiblityParams()
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity missing WR1 params", err)
		}
		ibek, err := ibeparams.GenerateChildKey(ctx, []byte(p.Namespace.Keccak256HI().MultihashString()))
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity has invalid WR1 params", err)
		}
		envkeyciphertext, err := ibek.EncryptMessage(ctx, envelopeAESK)
		if err != nil {
			return nil, wve.ErrW(wve.InvalidParameter, "namespace entity has invalid WR1 params", err)
		}
		wr1key.EnvelopeKey = envkeyciphertext
		outer.TBS.Keys = append(outer.TBS.Keys, asn1.NewExternal(wr1key))
	}

	//First marshal: sans revocations
	tbsDER, err := asn1.Marshal(outer.TBS)
	if err != nil {
		panic(err)
	}

	secret1 := p.Attester.Keyring[0].SecretCanonicalForm().Private.Content.(serdes.EntitySecretEd25519)
	ro := NewCommitmentRevocationSchemeInstance(p.SubjectLocation, true, secret1, tbsDER)
	outer.TBS.Revocations = append(outer.TBS.Revocations, ro.CanonicalForm())

	//Second marshal: with revocation
	tbsDER, err = asn1.Marshal(outer.TBS)
	if err != nil {
		panic(err)
	}

	sig, err := p.Attester.PrimarySigningKey().SignAttestation(ctx, tbsDER)
	if err != nil {
		panic(err)
	}
	outer.Signature = sig
	wo := serdes.WaveWireObject{
		Content: asn1.NewExternal(outer),
	}
	outerDER, err := asn1.Marshal(wo.Content)
	if err != nil {
		panic(err)
	}
	nd := NameDeclaration{}
	nd.SetCanonicalForm(&outer)
	nd.SetDecryptedBody(&body)

	// {
	// 	content, _, err := p.Attester.NameDeclarationRevocationDetails(&nd)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	hi := KECCAK256.Instance(content)
	// 	if len(nd.Revocations) == 0 {
	// 		panic("parsed nd no revocations\n")
	// 	}
	// 	expectedHash := HashSchemeInstanceFor(&nd.Revocations[0].(*CommitmentRevocationSchemeInstance).CRBody.Hash)
	// 	if hi.MultihashString() != expectedHash.MultihashString() {
	// 		panic("nd evocation mismatch")
	// 	} else {
	// 		fmt.Printf("nd revocation ok\n")
	// 	}
	// }

	return &RCreateNameDeclaration{
		NameDeclaration: &nd,
		DER:             outerDER,
	}, nil
}

type WR1NameDeclarationDecryptionContext interface {
	EntityByHashLoc(ctx context.Context, h HashSchemeInstance, loc LocationSchemeInstance) (*Entity, wve.WVE)
	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, delegable bool, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1DirectDecryptionKey(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
}

type PParseNameDeclaration struct {
	DER             []byte
	NameDeclaration *NameDeclaration
	Dctx            WR1NameDeclarationDecryptionContext
}
type RParseNameDeclaration struct {
	Result      *NameDeclaration
	IsMalformed bool
}

func ParseNameDeclaration(ctx context.Context, p *PParseNameDeclaration) (*RParseNameDeclaration, wve.WVE) {
	nd := p.NameDeclaration
	if nd == nil {
		wo := serdes.WaveWireObject{}
		rest, err := asn1.Unmarshal(p.DER, &wo.Content)
		if err != nil || len(rest) != 0 {
			return &RParseNameDeclaration{IsMalformed: true}, wve.Err(wve.MalformedDER, "DER did not parse")
		}
		ndcf, ok := wo.Content.Content.(serdes.WaveNameDeclaration)
		if !ok {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.UnexpectedObject, "DER is not a wave name declaration")
		}
		nd = &NameDeclaration{}
		werr := nd.SetCanonicalForm(&ndcf)
		if werr != nil {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, werr
		}
	}

	if p.Dctx == nil {
		//We can't resolve the attesting entity so we cannot progress any further
		return &RParseNameDeclaration{
			Result: nd,
		}, nil
	}
	//Get attesting entity
	attester, err := p.Dctx.EntityByHashLoc(ctx, nd.Attester, nd.AttesterLocation)
	if err != nil {
		return &RParseNameDeclaration{
			IsMalformed: true,
		}, wve.Err(wve.LookupFailure, "could not resolve attesting entity")
	}
	if attester == nil {
		return &RParseNameDeclaration{
			IsMalformed: true,
		}, wve.Err(wve.LookupFailure, "could not resolve attesting entity")
	}

	//Verify signature
	tbs, uerr := asn1.Marshal(nd.CanonicalForm.TBS)
	if uerr != nil {
		panic(uerr)
	}
	uerr = attester.VerifyingKey.VerifyAttestation(ctx, tbs, nd.CanonicalForm.Signature)
	if uerr != nil {
		return &RParseNameDeclaration{IsMalformed: true}, wve.Err(wve.InvalidSignature, "Name Declaration signature failed check")
	}

	//Try decode with keys
	var bodyDER []byte
	for _, k := range nd.CanonicalForm.TBS.Keys {
		_, ok := k.Content.(serdes.NameDeclarationKeyNone)
		if ok {
			//The body is not encrypted
			bodyDER = nd.CanonicalForm.TBS.Body
			break
		}
		if nd.WR1Extra == nil {
			nd.WR1Extra = &WR1Extra{}
		}
		wr1k, ok := k.Content.(serdes.NameDeclarationKeyWR1)
		if !ok {
			continue
		}

		ns := HashSchemeInstanceFor(&wr1k.Namespace)
		if !ns.Supported() {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		nsloc := LocationSchemeInstanceFor(&wr1k.NamespaceLocation)
		if !nsloc.Supported() {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		nd.WR1Extra.Namespace = ns
		nd.WR1Extra.NamespaceLocation = nsloc

		var envkey []byte

		if nd.WR1Extra.EnvelopeKey != nil {
			envkey = nd.WR1Extra.EnvelopeKey
		}

		if envkey == nil {
			uerr := p.Dctx.WR1IBEKeysForPartitionLabel(ctx, ns, func(k EntitySecretKeySchemeInstance) bool {
				var err error
				envkey, err = k.DecryptMessage(ctx, wr1k.EnvelopeKey)
				if err == nil {
					return false
				}
				return true
			})
			if uerr != nil {
				continue
			}
		}
		if len(envkey) == 0 {
			fmt.Printf("DC no outer key\n")
			continue
		}
		if len(envkey) != 16+12 {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		nd.WR1Extra.EnvelopeKey = envkey
		envelopeDER, ok := aesGCMDecrypt(envkey[:16], wr1k.Envelope, envkey[16:])
		if !ok {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		envelope := serdes.NameDeclarationWR1Envelope{}
		rest, err := asn1.Unmarshal(envelopeDER, &envelope)
		if len(rest) != 0 || err != nil {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		realpartition := make([][]byte, 20)
		for i := 0; i < 20; i++ {
			if len(envelope.Partition[i]) > 0 {
				realpartition[i] = envelope.Partition[i]
			}
		}
		nd.WR1Extra.Partition = realpartition

		//Try for full decryption
		var bodykey []byte
		uerr = p.Dctx.WR1OAQUEKeysForContent(ctx, ns, false, realpartition, func(k SlottedSecretKey) bool {
			var err error
			bodykey, err = k.DecryptMessageAsChild(ctx, envelope.BodyKey, realpartition)
			if err == nil {
				return false
			}
			return true
		})
		if uerr != nil {
			continue
		}
		if len(bodykey) == 0 {
			fmt.Printf("DC no inner key\n")
			continue
		}
		if len(bodykey) != 16+12 {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}

		//Now decode the main body
		bodyDER, ok = aesGCMDecrypt(bodykey[:16], nd.CanonicalForm.TBS.Body, bodykey[16:])
		if !ok {
			return &RParseNameDeclaration{
				IsMalformed: true,
			}, wve.Err(wve.MalformedObject, "invalid wr1 key")
		}
		break

	}
	if bodyDER == nil {
		return &RParseNameDeclaration{
			Result: nd,
		}, nil
	}
	body := serdes.NameDeclarationBody{}
	rest, uerr := asn1.Unmarshal(bodyDER, &body)
	if len(rest) != 0 || uerr != nil {
		return &RParseNameDeclaration{
			IsMalformed: true,
		}, wve.Err(wve.MalformedObject, "bad decrypted body DER")
	}
	nd.SetDecryptedBody(&body)
	return &RParseNameDeclaration{
		Result: nd,
	}, nil
	//We failed to decrypt using any of the keys
	return &RParseNameDeclaration{
		Result: nd,
	}, nil
}
