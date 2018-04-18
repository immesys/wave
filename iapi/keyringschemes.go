package iapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

func EntityKeyringSchemeInstanceFor(e asn1.External) (EntityKeyringSchemeInstance, error) {
	switch {
	case e.OID.Equal(serdes.PlaintextKeyringOID):
		return &KeyringPlaintext{SerdesForm: &e}, nil
	case e.OID.Equal(serdes.KeyringAES128_GCM_PBKDF2OID):
		ct, ok := e.Content.(serdes.KeyringAESCiphertext)
		if !ok {
			return nil, fmt.Errorf("invalid keyring")
		}
		return &AESKeyring{SerdesForm: &e, ciphertext: ct}, nil
	}
	return &UnsupportedKeyringScheme{}, nil
}
func NewEntityKeyringSchemeInstance(oid asn1.ObjectIdentifier) (EntityKeyringSchemeInstance, error) {
	switch {
	case oid.Equal(serdes.PlaintextKeyringOID):
		return &KeyringPlaintext{}, nil
	case oid.Equal(serdes.KeyringAES128_GCM_PBKDF2OID):
		return &AESKeyring{}, nil
	}
	return &UnsupportedKeyringScheme{}, nil
}

type UnsupportedKeyringScheme struct {
}

func (kr *UnsupportedKeyringScheme) Supported() bool {
	return false
}
func (kr *UnsupportedKeyringScheme) DecryptKeyring(ctx context.Context, params interface{}) (decodedForm *serdes.EntityKeyring, err error) {
	return nil, fmt.Errorf("keyring scheme is unsupported")
}
func (kr *UnsupportedKeyringScheme) EncryptKeyring(ctx context.Context, plaintext *serdes.EntityKeyring, params interface{}) (encodedForm *asn1.External, err error) {
	return nil, fmt.Errorf("keyring scheme is unsupported")
}

type KeyringPlaintext struct {
	SerdesForm *asn1.External
}

func (kr *KeyringPlaintext) Supported() bool {
	return true
}
func (kr *KeyringPlaintext) DecryptKeyring(ctx context.Context, params interface{}) (decodedForm *serdes.EntityKeyring, err error) {
	if kr.SerdesForm == nil {
		return nil, fmt.Errorf("this is not a curried keyring instance")
	}
	rv, ok := kr.SerdesForm.Content.(serdes.EntityKeyring)
	if !ok {
		return nil, fmt.Errorf("keyring is invalid")
	}
	return &rv, nil
}
func (kr *KeyringPlaintext) EncryptKeyring(ctx context.Context, plaintext *serdes.EntityKeyring, params interface{}) (encodedForm *asn1.External, err error) {
	rv := asn1.NewExternal(plaintext)
	return &rv, nil
}

type AESKeyring struct {
	SerdesForm *asn1.External
	ciphertext serdes.KeyringAESCiphertext
}

func (kr *AESKeyring) Supported() bool {
	return true
}
func (kr *AESKeyring) DecryptKeyring(ctx context.Context, params interface{}) (decodedForm *serdes.EntityKeyring, err error) {
	if kr.SerdesForm == nil {
		return nil, fmt.Errorf("this is not a curried keyring instance")
	}
	ppassphrase, ok := params.(*string)
	if !ok {
		return nil, fmt.Errorf("params must be a passphrase string")
	}
	passphrase := *ppassphrase
	//fmt.Printf("decrypt key %x\n", passphrase)
	aesk := pbkdf2.Key([]byte(passphrase), kr.ciphertext.Salt, kr.ciphertext.Iterations, 32, sha3.New512)

	block, err := aes.NewCipher(aesk)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	//We only use the key once, so the nonce is zero
	nonce := make([]byte, aesgcm.NonceSize())
	plaintext, err := aesgcm.Open(nil, nonce, kr.ciphertext.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	rv := serdes.EntityKeyring{}
	trailing, err := asn1.Unmarshal(plaintext, &rv)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal")
	}
	if len(trailing) != 0 {
		return nil, fmt.Errorf("trailing bytes")
	}
	return &rv, nil
}
func (kr *AESKeyring) EncryptKeyring(ctx context.Context, plaintext *serdes.EntityKeyring, params interface{}) (encodedForm *asn1.External, err error) {
	passphrase, ok := params.(string)
	if !ok {
		return nil, fmt.Errorf("requires a *string passphrase")
	}
	//fmt.Printf("encrypt key %x\n", passphrase)
	salt := make([]byte, 16)
	rand.Read(salt)
	iterations := 100000
	aesk := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha3.New512)
	ciphertext := serdes.KeyringAESCiphertext{
		Iterations: iterations,
		Salt:       salt,
	}
	block, err := aes.NewCipher(aesk)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesgcm.NonceSize())
	der, err := asn1.Marshal(*plaintext)
	if err != nil {
		return nil, err
	}
	ciphertext.Ciphertext = aesgcm.Seal(nil, nonce, der, nil)
	rv := asn1.NewExternal(ciphertext)
	return &rv, nil
}
