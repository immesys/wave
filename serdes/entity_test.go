package serdes

import (
	"encoding/base64"
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

const attestationHex string = `28 1B 06 0A 2B 06 01 04 01 83 8F 55 02 01 A0 0D
30 0B 02 01 04 30 03 02 01 06 02 01 05`

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

func TestCREncode(t *testing.T) {
	cr := CommitmentRevocation{T: time.Now()}
	ro := RevocationOption{
		Critical: true,
		Scheme:   asn1.NewExternal(cr),
	}
	fullDER, err := asn1.Marshal(ro)
	require.NoError(t, err)
	fmt.Printf("the full DER was %s\n", hex.EncodeToString(fullDER))
}

func TestAttestationDecode(t *testing.T) {
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
