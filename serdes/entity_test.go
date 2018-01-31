package serdes

import (
	"encoding/base64"
	"testing"

	"github.com/immesys/asn1"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testvec string = "KIGxBgorBgEEAYOPVQICoIGiMIGfMIGZMBgxAwIBASgRBgorBg" +
	"EEAYOPVQsBoAMEAQAwGjAYMQMCAQEoEQYKKwYBBAGDj1ULAaADBAEAMB4XDTAwMDEwMTAwMDAw" +
	"MFoXDTAwMDEwMTAwMDAwMFowPzA9AQEAKDgGCisGAQQBg49VCgGgKjAoKBEGCisGAQQBg49VCQ" +
	"GgAwQBACgTBgorBgEEAYOPVQgBoAUwAwwBMDAABAEA"

// 3003020140
// 3003800140

// func TestFooDecode3(t *testing.T) {
// 	ba, er := hex.DecodeString("30040C023634") //"") //"3003020140")
// 	require.NoError(t, er)
// 	v := FooMin{}
// 	rest, err := asn1.Unmarshal(ba, &v)
// 	require.NoError(t, err)
// 	spew.Dump(rest)
// 	spew.Dump(v)
// }

// func TestFooDecode(t *testing.T) {
// 	asn1.RegisterExternalType(asn1.ObjectIdentifier{1, 2, 2, 5}, &Bar{})
// 	ba, er := hex.DecodeString(strings.Replace("30 18 02 01 40 28 13 06 03 2A 02 05 A0 0C 30 0A 0C 05 68 65 6C 6C 6F 02 01 22", " ", "", -1))
// 	require.NoError(t, er)
// 	v := Foo{}
// 	rest, err := asn1.Unmarshal(ba, &v)
// 	require.NoError(t, err)
// 	spew.Dump(rest)
// 	spew.Dump(v)
// }

func TestEntityDecode(t *testing.T) {
	ba, err := base64.StdEncoding.DecodeString(testvec)
	require.NoError(t, err)

	v := WaveWireObject{}
	rest, err := asn1.Unmarshal(ba, &v.Content)
	require.NoError(t, err)
	spew.Dump(rest)
	spew.Dump(v)
}

// func TestFooDecode(t *testing.T) {
// 	ba, err := base64.StdEncoding.DecodeString(testvec)
// 	require.NoError(t, err)
//
// 	v := Foo{}
// 	rest, err := asn1.Unmarshal(ba, &v)
// 	require.NoError(t, err)
// 	spew.Dump(rest)
// 	spew.Dump(v)
// }
//
// func TestFooMinDeconde(t *testing.T) {
//
// 	ba, err := base64.StdEncoding.DecodeString(testvec2)
// 	require.NoError(t, err)
//
// 	v := Foo{}
// 	rest, err := asn1.Unmarshal(ba, &v)
// 	require.NoError(t, err)
// 	spew.Dump(rest)
// 	spew.Dump(v)
// }
