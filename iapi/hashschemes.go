package iapi

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

func HashSchemeFor(h asn1.External) HashScheme {
	panic("ni")
}
func NewHashScheme(oid asn1.ObjectIdentifier) HashScheme {
	panic("ni")
}

var _ HashScheme = &UnsupportedHashScheme{}

type UnsupportedHashScheme struct{}

func (hs *UnsupportedHashScheme) Supported() bool {
	return false
}
func (hs *UnsupportedHashScheme) Instance(ctx context.Context, input []byte) (HashSchemeInstance, error) {
	return nil, fmt.Errorf("unsupported hash scheme")
}

var _ HashScheme = &HashScheme_Sha3_256{}

type HashScheme_Sha3_256 struct{}

func (hs *HashScheme_Sha3_256) Supported() bool {
	return true
}
func (hs *HashScheme_Sha3_256) Instance(ctx context.Context, input []byte) (HashSchemeInstance, error) {
	hash := sha3.Sum256(input)
	return &HashSchemeInstance_Sha3_256{value: hash[:]}, nil
}

var _ HashScheme = &HashScheme_Keccak_256{}

type HashScheme_Keccak_256 struct{}

func (hs *HashScheme_Keccak_256) Supported() bool {
	return true
}
func (hs *HashScheme_Keccak_256) Instance(ctx context.Context, input []byte) (HashSchemeInstance, error) {
	hash := sha3.NewKeccak256().Sum(input)
	return &HashSchemeInstance_Sha3_256{value: hash[:]}, nil
}

var _ HashSchemeInstance = &HashSchemeInstance_Sha3_256{}

type HashSchemeInstance_Sha3_256 struct {
	value []byte
}

func (hs *HashSchemeInstance_Sha3_256) Supported() bool {
	return true
}
func (hs *HashSchemeInstance_Sha3_256) Value(ctx context.Context) ([]byte, error) {
	return hs.value, nil
}
func (hs *HashSchemeInstance_Sha3_256) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	ex := asn1.NewExternal(serdes.Sha3_256(hs.value))
	return &ex, nil
}

var _ HashSchemeInstance = &HashSchemeInstance_Keccak_256{}

type HashSchemeInstance_Keccak_256 struct {
	value []byte
}

func (hs *HashSchemeInstance_Keccak_256) Supported() bool {
	return true
}
func (hs *HashSchemeInstance_Keccak_256) Value(ctx context.Context) ([]byte, error) {
	return hs.value, nil
}
func (hs *HashSchemeInstance_Keccak_256) CanonicalForm(ctx context.Context) (*asn1.External, error) {
	ex := asn1.NewExternal(serdes.Keccak_256(hs.value))
	return &ex, nil
}
