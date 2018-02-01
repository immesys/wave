package serdes

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/immesys/asn1"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testvec string = "KIGxBgorBgEEAYOPVQICoIGiMIGfMIGZMBgxAwIBASgRBgorBg" +
	"EEAYOPVQsBoAMEAQAwGjAYMQMCAQEoEQYKKwYBBAGDj1ULAaADBAEAMB4XDTAwMDEwMTAwMDAw" +
	"MFoXDTAwMDEwMTAwMDAwMFowPzA9AQEAKDgGCisGAQQBg49VCgGgKjAoKBEGCisGAQQBg49VCQ" +
	"GgAwQBACgTBgorBgEEAYOPVQgBoAUwAwwBMDAABAEA"

const attestationTest string = "KIIC+QYKKwYBBAGDj1UCAaCCAukwggLlKDEGCisGAQQBg49VCQKgIwQhCJ29DD7P5zusFBm67SZ8" +
	"XaidjZ5iur2WHRfyL8N5s4tAMFIwUAEBAChLBgorBgEEAYOPVQoBoD0wOygRBgorBgEEAYOPVQkB" +
	"oAMEAQAoJgYKKwYBBAGDj1UIAaAYMBYMFGh0dHBzOi8vcmV2b2tlbWUuY29tMAAoggICBgorBgEE" +
	"AYOPVQMBoIIB8jCCAe4wggGAKDAGCisGAQQBg49VCQGgIgQgidvQw+z+c7rBQZuu0mfF2onY2eYr" +
	"q9lh0X8i/DebOLQoMAYKKwYBBAGDj1UJAaAiBCCJ29DD7P5zusFBm67SZ8XaidjZ5iur2WHRfyL8" +
	"N5s4tDAeFw0wMDAxMDEwMDAwMDBaFw0wMDAxMDEwMDAwMDBaKIGTBgorBgEEAYOPVQwCoIGEMIGB" +
	"KDAGCisGAQQBg49VCQGgIgQgidvQw+z+c7rBQZuu0mfF2onY2eYrq9lh0X8i/DebOLQCAQUwSjBI" +
	"KDAGCisGAQQBg49VCQGgIgQgidvQw+z+c7rBQZuu0mfF2onY2eYrq9lh0X8i/DebOLQMB2NhbGxB" +
	"UEkMC2Zvby9iYXIvYmF6MAAoYgYKKwYBBAGDj1UGAaBUMFIwLgYKKwYBBAGDj1UFAQQgidvQw+z+" +
	"c7rBQZuu0mfF2onY2eYrq9lh0X8i/DebOLQEIInb0MPs/nO6wUGbrtJnxdqJ2NnmK6vZYdF/Ivw3" +
	"mzi0MGQoMAYKKwYBBAGDj1UNAqAiBCCJ29DD7P5zusFBm67SZ8XaidjZ5iur2WHRfyL8N5s4tCgw" +
	"BgorBgEEAYOPVQ0BoCIEIInb0MPs/nO6wUGbrtJnxdqJ2NnmK6vZYdF/Ivw3mzi0MAIwAChUBgor" +
	"BgEEAYOPVQUBoEYwRAQgidvQw+z+c7rBQZuu0mfF2onY2eYrq9lh0X8i/DebOLQEIInb0MPs/nO6" +
	"wUGbrtJnxdqJ2NnmK6vZYdF/Ivw3mzi0"

const entityHex string = `28 81 B1 06 0A 2B 06 01 04 01 83 8F 55 02 02 A0
81 A2 30 81 9F 30 81 99 30 18 31 03 02 01 01 28
11 06 0A 2B 06 01 04 01 83 8F 55 0B 01 A0 03 04
01 00 30 1A 30 18 31 03 02 01 01 28 11 06 0A 2B
06 01 04 01 83 8F 55 0B 01 A0 03 04 01 00 30 1E
17 0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 17
0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 30 3F
30 3D 01 01 00 28 38 06 0A 2B 06 01 04 01 83 8F
55 0A 01 A0 2A 30 28 28 11 06 0A 2B 06 01 04 01
83 8F 55 09 01 A0 03 04 01 00 28 13 06 0A 2B 06
01 04 01 83 8F 55 08 01 A0 05 30 03 0C 01 30 30
00 04 01 00`

const attestationHex string = `28 82 01 2D 06 0A 2B 06 01 04 01 83 8F 55 02 01
A0 82 01 1D 30 82 01 19 30 81 FE 28 11 06 0A 2B
06 01 04 01 83 8F 55 09 01 A0 03 04 01 00 30 3F
30 3D 01 01 00 28 38 06 0A 2B 06 01 04 01 83 8F
55 0A 01 A0 2A 30 28 28 11 06 0A 2B 06 01 04 01
83 8F 55 09 01 A0 03 04 01 00 28 13 06 0A 2B 06
01 04 01 83 8F 55 08 01 A0 05 30 03 0C 01 30 30
00 28 81 A5 06 0A 2B 06 01 04 01 83 8F 55 03 01
A0 81 96 30 81 93 30 7A 28 11 06 0A 2B 06 01 04
01 83 8F 55 09 01 A0 03 04 01 00 28 11 06 0A 2B
06 01 04 01 83 8F 55 09 01 A0 03 04 01 00 30 1E
17 0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 17
0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 28 13
06 0A 2B 06 01 04 01 83 8F 55 0C 01 A0 05 30 03
02 01 01 30 00 28 1B 06 0A 2B 06 01 04 01 83 8F
55 06 01 A0 0D 30 0B 30 06 06 01 00 04 01 00 04
01 00 30 13 28 11 06 0A 2B 06 01 04 01 83 8F 55
0D 01 A0 03 04 01 00 30 00 28 16 06 0A 2B 06 01
04 01 83 8F 55 05 01 A0 08 30 06 04 01 00 04 01
00`

const noWireTypeAttest string = `30 0B 02 01 05 30 03 02 01 08 02 01 06`

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
	h := strings.Replace(attestationHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)

	v := WaveWireObject{}
	rest, err := asn1.Unmarshal(ba, &v.Content)
	require.NoError(t, err)
	spew.Dump(rest)
	spew.Dump(v)
}

func TestEntityEncode(t *testing.T) {
	e := WaveEntity{}
	pk := PublicEd25519([]byte{1, 7, 3})
	e.TBS.VerifyingKey = EntityPublicKey{
		Capabilities: DefaultEntityEd25519Capabilities(),
		Key:          asn1.NewExternal(pk),
	}
	e.TBS.Validity.NotBefore = time.Now()
	e.TBS.Validity.NotAfter = time.Now().Add(5 * time.Hour)
	der, err := asn1.Marshal(e.TBS)
	require.NoError(t, err)
	fmt.Printf("the TBS DER was %s\n", hex.EncodeToString(der))
	e.Signature = []byte{55, 66, 77}
	wireEntity := WaveWireObject{
		Content: asn1.NewExternal(e),
	}
	fullDER, err := asn1.Marshal(wireEntity.Content)
	require.NoError(t, err)
	fmt.Printf("the full DER was %s\n", hex.EncodeToString(fullDER))
}

// func TestCREncode(t *testing.T) {
// 	cr := CommitmentRevocation{T: time.Now()}
// 	ro := RevocationOption{
// 		Critical: true,
// 		Scheme:   asn1.NewExternal(cr),
// 	}
// 	fullDER, err := asn1.Marshal(ro)
// 	require.NoError(t, err)
// 	fmt.Printf("the full DER was %s\n", hex.EncodeToString(fullDER))
// }

func TestAttestationDecode1(t *testing.T) {
	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
	h := strings.Replace(attestationHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	fmt.Printf(h + "\n")
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := WaveWireObject{}
	_, err = asn1.Unmarshal(ba, &wo.Content)
	require.NoError(t, err)
	spew.Dump(wo.Content)

}

const JustAttestationBody = `30 81 95 30 7A 28 11 06 0A 2B 06 01 04 01 83 8F
55 09 01 A0 03 04 01 00 28 11 06 0A 2B 06 01 04
01 83 8F 55 09 01 A0 03 04 01 00 30 1E 17 0D 30
30 30 31 30 31 30 30 30 30 30 30 5A 17 0D 30 30
30 31 30 31 30 30 30 30 30 30 5A 28 13 06 0A 2B
06 01 04 01 83 8F 55 0C 01 A0 05 30 03 02 01 01
30 00 28 1B 06 0A 2B 06 01 04 01 83 8F 55 06 01
A0 0D 30 0B 30 06 06 01 00 04 01 00 04 01 00 30
15 28 13 06 0A 2B 06 01 04 01 83 8F 55 0D 01 A0
05 04 03 FF 44 33 30 00`

const JustAttestationBodyBig = `30 81 93 30 7A 28 11 06 0A 2B 06 01 04 01 83 8F
55 09 01 A0 03 04 01 00 28 11 06 0A 2B 06 01 04
01 83 8F 55 09 01 A0 03 04 01 00 30 1E 17 0D 30
30 30 31 30 31 30 30 30 30 30 30 5A 17 0D 30 30
30 31 30 31 30 30 30 30 30 30 5A 28 13 06 0A 2B
06 01 04 01 83 8F 55 0C 01 A0 05 30 03 02 01 01
30 00 28 1B 06 0A 2B 06 01 04 01 83 8F 55 06 01
A0 0D 30 0B 30 06 06 01 00 04 01 00 04 01 00 30
13 28 11 06 0A 2B 06 01 04 01 83 8F 55 0D 01 A0
03 04 01 00 30 00`

func TestAttestationBodyDecode(t *testing.T) {
	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
	h := strings.Replace(JustAttestationBody, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	fmt.Printf(h + "\n")
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := AttestationBody{}
	_, err = asn1.Unmarshal(ba, &wo)
	require.NoError(t, err)
	spew.Dump(wo)

}

const FooHex = `30 28 30 26 28 11 06 0A 2B 06 01 04 01 83 8F 55
09 01 A0 03 04 01 00 28 11 06 0A 2B 06 01 04 01
83 8F 55 09 01 A0 03 04 01 00`

func TestFoo(t *testing.T) {
	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
	h := strings.Replace(FooHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	fmt.Printf(h + "\n")
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := Foo{}
	_, err = asn1.Unmarshal(ba, &wo)
	require.NoError(t, err)
	spew.Dump(wo)

}

// func TestAttestationDecode2(t *testing.T) {
// 	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
// 	h := strings.Replace(noWireTypeAttest, " ", "", -1)
// 	h = strings.Replace(h, "\n", "", -1)
// 	fmt.Printf(h + "\n")
// 	ba, err := hex.DecodeString(h)
// 	require.NoError(t, err)
// 	wo := WaveAttestation{}
// 	_, err = asn1.Unmarshal(ba, &wo)
// 	require.NoError(t, err)
// 	spew.Dump(wo)
// }

const WaveAttLite = `
30 6E 30 54 28 11 06 0A 2B 06 01 04 01 83 8F 55
09 01 A0 03 04 01 00 30 3F 30 3D 01 01 00 28 38
06 0A 2B 06 01 04 01 83 8F 55 0A 01 A0 2A 30 28
28 11 06 0A 2B 06 01 04 01 83 8F 55 09 01 A0 03
04 01 00 28 13 06 0A 2B 06 01 04 01 83 8F 55 08
01 A0 05 30 03 0C 01 30 28 16 06 0A 2B 06 01 04
01 83 8F 55 05 01 A0 08 30 06 04 01 00 04 01 00`

/*
30 2F 30 15 28 11 06 0A 2B 06 01 04 01 83 8F 55
09 01 A0 03 04 01 00 30 00 28 16 06 0A 2B 06 01
04 01 83 8F 55 05 01 A0 08 30 06 04 01 00 04 01
00
*/
// func TestAttestationDecodeLite(t *testing.T) {
// 	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
// 	h := strings.Replace(WaveAttLite, " ", "", -1)
// 	h = strings.Replace(h, "\n", "", -1)
// 	fmt.Printf(h + "\n")
// 	ba, err := hex.DecodeString(h)
// 	require.NoError(t, err)
// 	wo := WaveAttestationLite{}
// 	_, err = asn1.Unmarshal(ba, &wo)
// 	require.NoError(t, err)
// 	spew.Dump(wo)
// }

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
