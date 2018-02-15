package iapi

import (
	"context"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

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
func (pt *PlaintextBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return intermediateForm, nil
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
func (u *UnsupportedBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return nil, fmt.Errorf("body scheme is unsupported")
}

// wr1
type WR1DecryptionContext interface {
	WR1VerifierBodyKey(ctx context.Context) AttestationVerifierKeySchemeInstance
	WR1EntityFromHash(ctx context.Context, hash HashScheme) (Entity, error)
	WR1OAQUEKeysForContent(ctx context.Context, dst HashScheme, slots [][]byte, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashScheme, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type WR1BodyScheme struct {
}

func (w *WR1BodyScheme) Supported() bool {
	return true
}
func (w *WR1BodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	return nil, nil, fmt.Errorf("body scheme is not fully unsupported")
}
func (w *WR1BodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return nil, fmt.Errorf("body scheme is unsupported")
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
	return
}
func (psk *PSKBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	pskec := ec.(PSKBodyEncryptionContext)
	encryptedForm = nil
	err = fmt.Errorf("no appropriate PSK found")
	pskec.GetEncryptPSK(ctx, intermediateForm, func(k EntitySecretKeySchemeInstance) bool {
		ct := serdes.PSKBodyCiphertext{}
		pub, serr := k.Public()
		if serr != nil {
			err = serr
			return false
		}
		cf, serr := pub.CanonicalForm(ctx)
		if serr != nil {
			err = serr
			return false
		}
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
