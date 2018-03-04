package iapi

import (
	"fmt"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

func LocationSchemeInstanceFor(e *asn1.External) LocationSchemeInstance {
	lsurl, ok := e.Content.(*LocationSchemeInstanceURL)
	if ok {
		return lsurl
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

var _ LocationSchemeInstance = &LocationSchemeInstanceURL{}

type LocationSchemeInstanceURL struct {
	SerdesForm *serdes.LocationURL
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

func NewLocationSchemeInstanceURL(url string, version int) LocationSchemeInstance {
	sf := &serdes.LocationURL{
		Value:   url,
		Version: version,
	}
	return &LocationSchemeInstanceURL{sf}
}
