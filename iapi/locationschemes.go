package iapi

import "github.com/immesys/wave/serdes"

var _ LocationSchemeInstance = &UnsupportedLocationSchemeInstance{}

type UnsupportedLocationSchemeInstance struct {
}

func (ls *UnsupportedLocationSchemeInstance) Supported() bool {
	return false
}
func (ls *UnsupportedLocationSchemeInstance) Equal(rhs LocationSchemeInstance) bool {
	return false
}

var _ LocationSchemeInstance = &LocationSchemeInstanceURL{}

type LocationSchemeInstanceURL struct {
	SerdesForm *serdes.LocationURL
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
