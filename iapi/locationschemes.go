package iapi

import (
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"golang.org/x/crypto/sha3"
)

func LocationSchemeInstanceFor(e *asn1.External) LocationSchemeInstance {
	//fmt.Printf("LOC SHEM INSTANCE\n")
	//spew.Dump(e)
	lsurl, ok := e.Content.(serdes.LocationURL)
	if ok {
		return &LocationSchemeInstanceURL{
			SerdesForm: &lsurl,
		}
	}
	return &UnsupportedLocationSchemeInstance{}
}

var _ LocationSchemeInstance = &UnsupportedLocationSchemeInstance{}

type UnsupportedLocationSchemeInstance struct {
}

func (ls *UnsupportedLocationSchemeInstance) Supported() bool {
	return false
}
func (ls *UnsupportedLocationSchemeInstance) Equal(rhs LocationSchemeInstance) bool {
	return false
}
func (ls *UnsupportedLocationSchemeInstance) CanonicalForm() (*asn1.External, error) {
	return nil, fmt.Errorf("Location scheme is unsupported")
}
func (ls *UnsupportedLocationSchemeInstance) IdHash() [32]byte {
	return [32]byte{}
}

var _ LocationSchemeInstance = &LocationSchemeInstanceURL{}

type LocationSchemeInstanceURL struct {
	SerdesForm *serdes.LocationURL
	idhash     []byte
}

func (ls *LocationSchemeInstanceURL) CanonicalForm() (*asn1.External, error) {
	ex := asn1.NewExternal(*ls.SerdesForm)
	return &ex, nil
}
func (ls *LocationSchemeInstanceURL) Supported() bool {
	return true
}
func (ls *LocationSchemeInstanceURL) Equal(rhs LocationSchemeInstance) bool {
	rhurl, ok := rhs.(*LocationSchemeInstanceURL)
	if !ok {
		return false
	}
	return rhurl.SerdesForm.Value == ls.SerdesForm.Value && rhurl.SerdesForm.Version == ls.SerdesForm.Version
}
func (ls *LocationSchemeInstanceURL) IdHash() [32]byte {
	if ls.idhash == nil {
		h := sha3.New256()
		h.Write([]byte("LocationSchemeInstanceURL"))
		h.Write([]byte(fmt.Sprintf("%04d:%s", ls.SerdesForm.Version, ls.SerdesForm.Value)))
		ls.idhash = h.Sum(nil)
	}
	rv := [32]byte{}
	copy(rv[:], ls.idhash)
	return rv
}

func NewLocationSchemeInstanceURL(url string, version int) LocationSchemeInstance {
	sf := &serdes.LocationURL{
		Value:   url,
		Version: version,
	}
	return &LocationSchemeInstanceURL{SerdesForm: sf}
}
