package iapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

var ErrDecryptBodyMalformed = errors.New("body is malformed")

func AttestationBodySchemeFor(ex *asn1.External) AttestationBodyScheme {
	if ex.OID.Equal(serdes.UnencryptedBodyOID) {
		return &PlaintextBodyScheme{}
	}
	if ex.OID.Equal(serdes.WR1BodyOID) {
		return &WR1BodyScheme{}
	}
	return &UnsupportedBodyScheme{}
}

// plaintext
var _ AttestationBodyScheme = &PlaintextBodyScheme{}

type PlaintextBodyScheme struct {
	//CanonicalForm *asn1.External
}

var PLAINTEXTBODYSCHEME = &PlaintextBodyScheme{}

func NewPlaintextBodyScheme() *PlaintextBodyScheme {
	return &PlaintextBodyScheme{}
}
func (pt *PlaintextBodyScheme) Supported() bool {
	return true
}
func (pt *PlaintextBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	rv := canonicalForm.TBS.Body.Content.(serdes.AttestationBody)
	return &rv, nil, nil
}
func (pt *PlaintextBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	return intermediateForm, nil, nil
}

// unsupported
var _ AttestationBodyScheme = &UnsupportedBodyScheme{}

type UnsupportedBodyScheme struct {
}

func (u *UnsupportedBodyScheme) Supported() bool {
	return false
}
func (u *UnsupportedBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	return nil, nil, fmt.Errorf("body scheme is unsupported")
}
func (u *UnsupportedBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	return nil, nil, fmt.Errorf("body scheme is unsupported")
}

// wr1
type WR1DecryptionContext interface {
	WR1VerifierBodyKey(ctx context.Context) []byte
	WR1ProverBodyKey(ctx context.Context) []byte
	//WR1EntityFromHash(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, error)
	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1DirectDecryptionKey(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type WR1BodyScheme struct {
}

type WR1Extra struct {
	Partition       [][]byte
	VerifierBodyKey []byte
	ProverBodyKey   []byte
}

func (w *WR1BodyScheme) Supported() bool {
	return true
}

func (w *WR1BodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	fmt.Printf("dc AA\n")
	wr1body, ok := canonicalForm.TBS.Body.Content.(serdes.WR1BodyCiphertext)
	if !ok {
		fmt.Printf("dc A1\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	wr1dctx, ok := dc.(WR1DecryptionContext)
	if !ok {
		fmt.Printf("dc failed\n")
		return nil, nil, nil
	}
	subjectHI := HashSchemeInstanceFor(&canonicalForm.TBS.Subject)
	if !subjectHI.Supported() {
		fmt.Printf("wrong HI\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	//Step 0: if there is a symmetric key in the decrytion context we should use that
	vbody := serdes.WR1VerifierBody{}
	attverifierkey := wr1dctx.WR1VerifierBodyKey(ctx)
	fmt.Printf("dc BB\n")
	if attverifierkey != nil {
		fmt.Printf("found att verifier key %d\n", len(attverifierkey))
		verifierBodyKey := attverifierkey[:16]
		verifierBodyNonce := attverifierkey[16:]
		verifierBodyDER, ok := aesGCMDecrypt(verifierBodyKey, wr1body.VerifierBodyCiphertext, verifierBodyNonce)
		if !ok {
			fmt.Printf("case B\n")
			return nil, nil, ErrDecryptBodyMalformed
		}
		trailing, err := asn1.Unmarshal(verifierBodyDER, &vbody)
		if err != nil || len(trailing) != 0 {
			fmt.Printf("case C\n")
			return nil, nil, ErrDecryptBodyMalformed
		}
		rv := &serdes.AttestationBody{
			VerifierBody: vbody.AttestationVerifierBody,
		}
		return rv, nil, nil
	}
	//We did not have an attestation verifier key in the decryption context, try
	//to decrypt in the prover role

	fmt.Printf("dc A\n")

	//Step 1: decode the label
	//First try get the envelope key using asymmetric direct encryption
	var envelopeKey []byte
	//Actually first check for prover key in dctx
	explicitProverBodyKey := wr1dctx.WR1ProverBodyKey(ctx)
	if explicitProverBodyKey != nil {
		envelopeKey = explicitProverBodyKey[:28]
	}
	if envelopeKey == nil {
		err = wr1dctx.WR1DirectDecryptionKey(ctx, subjectHI, func(k EntitySecretKeySchemeInstance) bool {
			fmt.Printf("trying direct key %p\n", k)
			var err error
			envelopeKey, err = k.DecryptMessage(ctx, wr1body.EnvelopeKey_Curve25519)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			fmt.Printf("dc D\n")
			return nil, nil, err
		}
	}
	fmt.Printf("dc B\n")
	if envelopeKey == nil {
		fmt.Printf("XXXXXXX dc C\n")
		//Try using label secrets
		err := wr1dctx.WR1IBEKeysForPartitionLabel(ctx, subjectHI, func(k EntitySecretKeySchemeInstance) bool {
			var err error
			envelopeKey, err = k.DecryptMessage(ctx, wr1body.EnvelopeKey_IBE_BN256)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if envelopeKey == nil {
		fmt.Printf("dc no label\n")
		return nil, nil, nil
	}
	//The key is actually 16 bytes of AES key + 12 bytes of GCM nonce
	if len(envelopeKey) != 16+12 {
		fmt.Printf("dc E\n")
		return nil, nil, ErrDecryptBodyMalformed
	}

	//Lets actually decrypt the envelope DER
	envelopeDER, ok := aesGCMDecrypt(envelopeKey[:16], wr1body.EnvelopeCiphertext, envelopeKey[16:])
	if !ok {
		fmt.Printf("dc F\n")
		return nil, nil, ErrDecryptBodyMalformed
	} else {
		fmt.Printf("envelope decrypted ok\n")
	}

	envelope := serdes.WR1Envelope{}
	trailing, err := asn1.Unmarshal(envelopeDER, &envelope)
	if err != nil || len(trailing) != 0 {
		fmt.Printf("dc G\n")
		return nil, nil, ErrDecryptBodyMalformed
	}

	fmt.Printf("dc2 1\n")
	//We know the partition labels now
	rvextra := &WR1Extra{Partition: envelope.Partition}
	extra = rvextra
	var bodyKeys []byte
	if explicitProverBodyKey != nil {
		bodyKeys = explicitProverBodyKey[28:]
	}
	if bodyKeys == nil {
		//Try decrypt with those labels
		err = wr1dctx.WR1OAQUEKeysForContent(ctx, subjectHI, envelope.Partition, func(k SlottedSecretKey) bool {
			fmt.Printf("got an oq key\n")
			var err error
			bodyKeys, err = k.DecryptMessageAsChild(ctx, envelope.BodyKeys_OAQUE, envelope.Partition)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			//Why would we get an error here?
			panic(err)
		}
	}
	if bodyKeys == nil {
		fmt.Printf("no body keys obtained\n")
		//We could not decrypt the dot. Just return with whatever we have
		return nil, extra, nil
	}
	if len(bodyKeys) != 16+12+16+12 {
		fmt.Printf("lbk\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	proverBodyKey := bodyKeys[0:16]
	proverBodyNonce := bodyKeys[16:28]
	verifierBodyKey := bodyKeys[28:44]
	verifierBodyNonce := bodyKeys[44:56]

	pbody := serdes.WR1ProverBody{}

	proverBodyDER, ok := aesGCMDecrypt(proverBodyKey, wr1body.ProverBodyCiphertext, proverBodyNonce)
	if !ok {
		fmt.Printf("keyfail 1\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	verifierBodyDER, ok := aesGCMDecrypt(verifierBodyKey, wr1body.VerifierBodyCiphertext, verifierBodyNonce)
	if !ok {
		fmt.Printf("keyfail 2\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	trailing, err = asn1.Unmarshal(proverBodyDER, &pbody)
	if err != nil || len(trailing) != 0 {
		fmt.Printf("keyfail 3\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	trailing, err = asn1.Unmarshal(verifierBodyDER, &vbody)
	if err != nil || len(trailing) != 0 {
		fmt.Printf("keyfail 4\n")
		fmt.Printf("trailing: %x\n", trailing)
		fmt.Printf("err: %v\n", err)
		return nil, nil, ErrDecryptBodyMalformed
	}
	rv := &serdes.AttestationBody{
		VerifierBody:          vbody.AttestationVerifierBody,
		ProverPolicyAddendums: pbody.Addendums,
		ProverExtensions:      pbody.Extensions,
	}
	if explicitProverBodyKey == nil {
		explicitProverBodyKey = make([]byte, 28*3)
		copy(explicitProverBodyKey[0:28], envelopeKey)
		copy(explicitProverBodyKey[28:], bodyKeys)
	}
	rvextra.VerifierBodyKey = bodyKeys[28:56] //include nonce
	rvextra.ProverBodyKey = explicitProverBodyKey
	fmt.Printf("dc Z\n")
	return rv, rvextra, nil
}

func (w *WR1BodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	//Step 0 generate the WR1 keys
	// - IBE key using the domain visibility from the policy
	// - OAQUE key using the WR1 partition from the entity
	// - TODO: e2e encryption keys
	// - TODO: in-order parent dot key delegation
	//  basically we are only supporting same or broadening delegation in/out of order
	//  to support narrowing in-order we would want to include extra WR1 keys in the dot
	plaintextBody := intermediateForm.TBS.Body.Content.(serdes.AttestationBody)
	// policy, err := PolicySchemeInstanceFor(&plaintextBody.VerifierBody.Policy)
	// if err != nil {
	// 	return nil, err
	// }
	visibilityEntity := policy.WR1DomainEntity()
	var visibilityID string = "$GLOBAL"
	if visibilityEntity != nil {
		visibilityID = fmt.Sprintf("%s:%x", visibilityEntity.OID().String(), visibilityEntity.Value())
	}
	bodySlots := policy.WR1Partition()
	visibilityParams, err := subject.WR1_DomainVisiblityParams()
	if err != nil {
		return nil, nil, err
	}
	visibilityKey, err := visibilityParams.GenerateChildKey(ctx, []byte(visibilityID))
	if err != nil {
		return nil, nil, err
	}
	directKey, err := subject.WR1_DirectEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	bodyParams, err := subject.WR1_BodyParams()
	if err != nil {
		return nil, nil, err
	}
	oaqueBodyKey, err := bodyParams.GenerateChildKey(ctx, bodySlots)
	if err != nil {
		return nil, nil, err
	}

	//Ok now we have the key material we need to encrypt. Lets generate the delegated key material
	delegatedVisibilityKey, err := attester.WR1LabelKey(ctx, []byte(visibilityID))
	if err != nil {
		return nil, nil, err
	}
	delegatedBodyKey, err := attester.WR1BodyKey(ctx, bodySlots)
	if err != nil {
		return nil, nil, err
	}

	//Ok now lets generate the symmetric encryption keys
	bodyKeys := make([]byte, 16+12+16+12)
	if _, e := rand.Read(bodyKeys); e != nil {
		panic(e)
	}
	proverBodyKey := bodyKeys[0:16]
	proverBodyNonce := bodyKeys[16:28]
	verifierBodyKey := bodyKeys[28:44]
	verifierBodyNonce := bodyKeys[44:56]
	ciphertext := &serdes.WR1BodyCiphertext{}
	envelope := &serdes.WR1Envelope{}
	proverBody := &serdes.WR1ProverBody{}
	verifierBody := &serdes.WR1VerifierBody{}

	//Copy the fields
	proverBody.Addendums = plaintextBody.ProverPolicyAddendums
	dvkSCF := delegatedVisibilityKey.SecretCanonicalForm()
	proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(serdes.WR1DomainVisibilityKey_IBE_BN256(*dvkSCF)))
	dbkSCF := delegatedBodyKey.SecretCanonicalForm()
	proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(serdes.WR1PartitionKey_OAQUE_BN256_s20(*dbkSCF)))
	proverBody.Extensions = plaintextBody.ProverExtensions
	verifierBody.AttestationVerifierBody = plaintextBody.VerifierBody

	//Get the DER
	proverBodyDER, err := asn1.Marshal(*proverBody)
	if err != nil {
		return nil, nil, err
	}
	verifierBodyDER, err := asn1.Marshal(*verifierBody)
	if err != nil {
		return nil, nil, err
	}

	//Encrypt the DER using the given keys
	ciphertext.ProverBodyCiphertext = aesGCMEncrypt(proverBodyKey, proverBodyDER, proverBodyNonce)
	ciphertext.VerifierBodyCiphertext = aesGCMEncrypt(verifierBodyKey, verifierBodyDER, verifierBodyNonce)

	//Create the OAQUE ciphertext
	envelope.BodyKeys_OAQUE, err = oaqueBodyKey.EncryptMessage(ctx, bodyKeys)
	if err != nil {
		return nil, nil, err
	}
	envelope.Partition = bodySlots

	//Get the envelope DER
	envelopeDER, err := asn1.Marshal(*envelope)
	if err != nil {
		return nil, nil, err
	}

	//Generate a key for the envelope
	envelopeSymKey := make([]byte, 16+12)
	rand.Read(envelopeSymKey)

	//Encrypt under the destination's curve25519 key
	ciphertext.EnvelopeKey_Curve25519, err = directKey.EncryptMessage(ctx, envelopeSymKey)
	if err != nil {
		return nil, nil, err
	}
	//Encrypt under the destinations IBE key
	ciphertext.EnvelopeKey_IBE_BN256, err = visibilityKey.EncryptMessage(ctx, envelopeSymKey)
	if err != nil {
		return nil, nil, err
	}
	ciphertext.EnvelopeCiphertext = aesGCMEncrypt(envelopeSymKey[:16], envelopeDER, envelopeSymKey[16:])
	//Return the intermediate form with the body replaced
	intermediateForm.TBS.Body = asn1.NewExternal(*ciphertext)
	explicitProverBodyKey := make([]byte, 28*3)
	copy(explicitProverBodyKey[0:28], envelopeSymKey)
	copy(explicitProverBodyKey[28:], bodyKeys)

	rvextra := &WR1Extra{
		Partition:       bodySlots,
		VerifierBodyKey: bodyKeys[28:56],
		ProverBodyKey:   explicitProverBodyKey,
	}
	return intermediateForm, rvextra, nil
}

type PSKExtra struct {
	VerifierBodyKey []byte
}
type PSKBodyDecryptionContext interface {
	GetDecryptPSK(ctx context.Context, dst HashScheme, public EntityKeySchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type PSKBodyEncryptionContext interface {
	GetEncryptPSK(ctx context.Context, body *serdes.WaveAttestation, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type PSKBodyScheme struct {
	CanonicalForm *asn1.External
}

func (psk *PSKBodyScheme) Supported() bool {
	return true
}
func (psk *PSKBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	ciphertext := canonicalForm.TBS.Body.Content.(serdes.PSKBodyCiphertext)
	pk, err := EntityKeySchemeInstanceFor(&ciphertext.EncryptedUnder)
	if err != nil {
		return nil, nil, err
	}
	subject := HashSchemeFor(canonicalForm.TBS.Subject)
	pskdc := dc.(PSKBodyDecryptionContext)
	decodedForm = nil
	err = fmt.Errorf("no suitable PSK found")
	pskdc.GetDecryptPSK(ctx, subject, pk, func(k EntitySecretKeySchemeInstance) bool {
		der, serr := k.DecryptMessage(ctx, ciphertext.AttestationBodyCiphetext)
		if serr == nil {
			rv := serdes.AttestationBody{}
			trailing, serr := asn1.Unmarshal(der, rv)
			if serr != nil {
				err = serr
				return false
			}
			if len(trailing) != 0 {
				err = fmt.Errorf("trailing bytes found")
				return false
			}
			decodedForm = &rv
			err = nil
			return false
		}
		return true
	})
	//probably need two layers so that verifiers can read the dot without knowing
	//the PSK. The extra key (ephemeral just for this dot) should be returned
	//in the extra
	panic("need to do PSK extra")
	return
}
func (psk *PSKBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	pskec := ec.(PSKBodyEncryptionContext)
	encryptedForm = nil
	err = fmt.Errorf("no appropriate PSK found")
	pskec.GetEncryptPSK(ctx, intermediateForm, func(k EntitySecretKeySchemeInstance) bool {
		ct := serdes.PSKBodyCiphertext{}
		pub := k.Public()
		cf := pub.CanonicalForm()
		ct.EncryptedUnder = *cf
		der, serr := asn1.Marshal(intermediateForm)
		if serr != nil {
			err = serr
			return false
		}
		ciphertext, serr := pub.EncryptMessage(ctx, der)
		if serr != nil {
			err = serr
			return false
		}
		ct.AttestationBodyCiphetext = ciphertext
		rv := *intermediateForm
		rv.TBS.Body = asn1.NewExternal(ct)
		encryptedForm = &rv
		return false
		//ephemeralKey :=
		//ciphertext, err := k.EncryptMessageDH(ctx, to, content)
	})
	return
}
