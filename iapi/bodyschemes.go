package iapi

import (
	"context"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

func AttestationBodySchemeFor(ex *asn1.External) AttestationBodyScheme {
	if ex.OID.Equal(serdes.UnencryptedBodyOID) {
		return &PlaintextBodyScheme{CanonicalForm: ex}
	}
	if ex.OID.Equal(serdes.WR1BodyOID) {
		return &WR1BodyScheme{CanonicalForm: ex}
	}
	return &UnsupportedBodyScheme{CanonicalForm: ex}
}

// plaintext
var _ AttestationBodyScheme = &PlaintextBodyScheme{}

type PlaintextBodyScheme struct {
	CanonicalForm *asn1.External
}

func (pt *PlaintextBodyScheme) Supported() bool {
	return true
}
func (pt *PlaintextBodyScheme) DecryptBody(ctx context.Context, dc DecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error) {
	rv := pt.CanonicalForm.Content.(serdes.AttestationBody)
	return &rv, nil
}
func (pt *PlaintextBodyScheme) EncryptBody(ctx context.Context, ec EncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return intermediateForm, nil
}

// unsupported
var _ AttestationBodyScheme = &UnsupportedBodyScheme{}

type UnsupportedBodyScheme struct {
	CanonicalForm *asn1.External
}

func (u *UnsupportedBodyScheme) Is(oid asn1.ObjectIdentifier) bool {
	return u.CanonicalForm.OID.Equal(oid)
}
func (u *UnsupportedBodyScheme) Supported() bool {
	return false
}
func (u *UnsupportedBodyScheme) DecryptBody(ctx context.Context, dc DecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error) {
	return nil, fmt.Errorf("body scheme %s is unsupported", u.CanonicalForm.OID.String())
}
func (u *UnsupportedBodyScheme) EncryptBody(ctx context.Context, ec EncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return nil, fmt.Errorf("body scheme %s is unsupported", u.CanonicalForm.OID.String())
}

// wr1
type WR1DecryptionContext interface {
	WR1VerifierBodyKey(ctx context.Context) AttestationVerifierKeyScheme
	WR1EntityFromHash(ctx context.Context, hash HashScheme) (Entity, error)
	WR1OAQUEKeysForContent(ctx context.Context, dst HashScheme, slots [][]byte, onResult func(k EntitySecretKeyScheme) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashScheme, onResult func(k EntitySecretKeyScheme) bool) error
}
type WR1BodyScheme struct {
	CanonicalForm *asn1.External
}

func (w *WR1BodyScheme) Is(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(serdes.WR1BodyOID)
}
func (w *WR1BodyScheme) Supported() bool {
	return true
}
func (w *WR1BodyScheme) DecryptBody(ctx context.Context, dc DecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error) {
	return nil, fmt.Errorf("body scheme %s is not fully unsupported", w.CanonicalForm.OID.String())
}
func (w *WR1BodyScheme) EncryptBody(ctx context.Context, ec EncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	return nil, fmt.Errorf("body scheme %s is unsupported", w.CanonicalForm.OID.String())
}

type PSKBodyDecryptionContext interface {
	GetDecryptPSK(ctx context.Context, dst HashScheme, public EntityKeyScheme, onResult func(k EntitySecretKeyScheme) bool) error
}
type PSKBodyEncryptionContext interface {
	GetEncryptPSK(ctx context.Context, body *serdes.WaveAttestation, onResult func(k EntitySecretKeyScheme) bool) error
}
type PSKBodyScheme struct {
	CanonicalForm *asn1.External
}

func (psk *PSKBodyScheme) Is(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(serdes.PSKBodySchemeOID)
}
func (psk *PSKBodyScheme) Supported() bool {
	return true
}
func (psk *PSKBodyScheme) DecryptBody(ctx context.Context, dc DecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, err error) {
	ciphertext := canonicalForm.TBS.Body.Content.(serdes.PSKBodyCiphertext)
	pk := EntityKeySchemeFor(&ciphertext.EncryptedUnder)
	subject := HashSchemeFor(canonicalForm.TBS.Subject)
	pskdc := dc.(PSKBodyDecryptionContext)
	decodedForm = nil
	err = fmt.Errorf("no suitable PSK found")
	pskdc.GetDecryptPSK(ctx, subject, pk, func(k EntitySecretKeyScheme) bool {
		der, serr := k.DecryptMessageDH(ctx, ciphertext.AttestationBodyCiphetext)
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
func (psk *PSKBodyScheme) EncryptBody(ctx context.Context, ec EncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, err error) {
	pskec := ec.(PSKBodyEncryptionContext)
	encryptedForm = nil
	err = fmt.Errorf("no appropriate PSK found")
	pskec.GetEncryptPSK(ctx, intermediateForm, func(k EntitySecretKeyScheme) bool {
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
		ciphertext, serr := pub.EncryptMessageDH(ctx, der)
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
