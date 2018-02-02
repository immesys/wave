package serdes

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/immesys/asn1"

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

const entityHexComment string = `28 81 C7 06 0A 2B 06 01 04 01 83 8F 55 02 02 A0
81 B8 30 81 B5 30 81 AF 30 18 31 03 02 01 01 28
11 06 0A 2B 06 01 04 01 83 8F 55 0B 01 A0 03 04
01 00 30 1A 30 18 31 03 02 01 01 28 11 06 0A 2B
06 01 04 01 83 8F 55 0B 01 A0 03 04 01 00 30 1E
17 0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 17
0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 30 3F
30 3D 01 01 00 28 38 06 0A 2B 06 01 04 01 83 8F
55 0A 01 A0 2A 30 28 28 11 06 0A 2B 06 01 04 01
83 8F 55 09 01 A0 03 04 01 00 28 13 06 0A 2B 06
01 04 01 83 8F 55 08 01 A0 05 30 03 0C 01 30 A0
09 0C 07 43 6F 6E 74 61 63 74 A1 09 0C 07 43 6F
6D 6D 65 6E 74 30 00 04 01 00`

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

func TestEntityDecode(t *testing.T) {
	h := strings.Replace(entityHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)

	v := WaveWireObject{}
	rest, err := asn1.Unmarshal(ba, &v.Content)
	require.NoError(t, err)
	_ = rest
	_ = v
	//spew.Dump(rest)
	//spew.Dump(v)
}

func TestEntityDecode2(t *testing.T) {
	h := strings.Replace(entityHexComment, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)

	v := WaveWireObject{}
	rest, err := asn1.Unmarshal(ba, &v.Content)
	require.NoError(t, err)
	_ = rest
	_ = v
	//spew.Dump(rest)
	//spew.Dump(v)
}

func TestEntityEncode(t *testing.T) {
	e := WaveEntity{}
	pk := EntityPublicEd25519([]byte{1, 7, 3})
	e.TBS.VerifyingKey = EntityPublicKey{
		Capabilities: []int{1, 2, 3},
		Key:          asn1.NewExternal(pk),
	}
	e.TBS.Validity.NotBefore = time.Now()
	e.TBS.Validity.NotAfter = time.Now().Add(5 * time.Hour)
	_, err := asn1.Marshal(e.TBS)
	require.NoError(t, err)
	e.Signature = []byte{55, 66, 77}
	wireEntity := WaveWireObject{
		Content: asn1.NewExternal(e),
	}
	_, err = asn1.Marshal(wireEntity.Content)
	require.NoError(t, err)
}

func TestEntityEncode2(t *testing.T) {
	e := WaveEntity{}
	pk := EntityPublicEd25519([]byte{1, 7, 3})
	e.TBS.VerifyingKey = EntityPublicKey{
		Capabilities: []int{1, 2, 3},
		Key:          asn1.NewExternal(pk),
	}
	e.TBS.Validity.NotBefore = time.Now()
	e.TBS.Comment = "hello"

	e.TBS.Validity.NotAfter = time.Now().Add(5 * time.Hour)
	_, err := asn1.Marshal(e.TBS)
	require.NoError(t, err)
	e.Signature = []byte{55, 66, 77}
	wireEntity := WaveWireObject{
		Content: asn1.NewExternal(e),
	}
	der, err := asn1.Marshal(wireEntity.Content)
	require.NoError(t, err)
	fmt.Printf("der was: %x\n", der)
}

func TestAttestationEncode(t *testing.T) {
	a := WaveAttestation{}
	subject := Keccak_256("hello")
	a.TBS.Subject = asn1.NewExternal(subject)

	b := AttestationBody{}
	b.VerifierBody.Attester = asn1.NewExternal(Keccak_256("world"))
	b.VerifierBody.Policy = asn1.NewExternal(TrustLevel{3})
	b.VerifierBody.Subject = asn1.NewExternal(subject)
	b.VerifierBody.Validity.NotAfter = time.Now().Add(50 * time.Minute)
	b.VerifierBody.Validity.NotBefore = time.Now()

	//	b.ProverPolicyAddendums = append(b.ProverPolicyAddendums, asn1.NewExternal(WR1PartitionKey_OAQUE_BN256_s20("hello")))
	sigok := SignedOuterKey{}
	sigok.TBS.OuterSignatureScheme = EphemeralEd25519OID
	sigok.TBS.VerifyingKey = []byte("hello")
	sigok.Signature = []byte("foobar")
	b.VerifierBody.OuterSignatureBinding = asn1.NewExternal(sigok)
	outersig := Ed25519OuterSignature{}
	outersig.VerifyingKey = []byte("fhelllo")
	outersig.Signature = []byte("haai")
	a.TBS.Body = asn1.NewExternal(b)
	a.OuterSignature = asn1.NewExternal(outersig)

	wireEntity := WaveWireObject{
		Content: asn1.NewExternal(a),
	}
	_, err := asn1.Marshal(wireEntity.Content)
	require.NoError(t, err)
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
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := WaveWireObject{}
	_, err = asn1.Unmarshal(ba, &wo.Content)
	require.NoError(t, err)

	//spew.Dump(wo.Content)

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
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := AttestationBody{}
	_, err = asn1.Unmarshal(ba, &wo)
	require.NoError(t, err)
	//spew.Dump(wo)
}

func TestAttestationGob(t *testing.T) {
	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
	h := strings.Replace(attestationHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(t, err)
	wo := WaveWireObject{}
	_, err = asn1.Unmarshal(ba, &wo.Content)
	require.NoError(t, err)
	bf := bytes.Buffer{}
	gobenc := gob.NewEncoder(&bf)
	err = gobenc.Encode(wo)
	require.NoError(t, err)
	gobdec := gob.NewDecoder(&bf)
	readback := WaveWireObject{}
	err = gobdec.Decode(&readback)
	require.NoError(t, err)

	der, err := asn1.Marshal(wo.Content)
	require.NoError(t, err)

	fmt.Printf("expected: %x\n", ba)
	fmt.Printf("got     : %x\n", der)
	require.EqualValues(t, ba, der)

}

func BenchmarkGobEncodeAttestation(b *testing.B) {
	h := strings.Replace(attestationHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(b, err)
	wo := WaveWireObject{}
	_, err = asn1.Unmarshal(ba, &wo.Content)
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf := bytes.Buffer{}
		gobenc := gob.NewEncoder(&bf)
		err = gobenc.Encode(wo)
		require.NoError(b, err)
	}
}
func BenchmarkGobDecodeAttestation(b *testing.B) {
	//ba, err := base64.StdEncoding.DecodeString(attestationTest)
	h := strings.Replace(attestationHex, " ", "", -1)
	h = strings.Replace(h, "\n", "", -1)
	ba, err := hex.DecodeString(h)
	require.NoError(b, err)
	wo := WaveWireObject{}
	_, err = asn1.Unmarshal(ba, &wo.Content)
	require.NoError(b, err)
	obf := bytes.Buffer{}
	gobenc := gob.NewEncoder(&obf)
	err = gobenc.Encode(wo)
	require.NoError(b, err)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bf := bytes.NewBuffer(obf.Bytes())
		gobdec := gob.NewDecoder(bf)
		readback := WaveWireObject{}
		err = gobdec.Decode(&readback)
		require.NoError(b, err)
	}
}
func BenchmarkEntityEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e := WaveEntity{}
		pk := EntityPublicEd25519([]byte{1, 7, 3})
		e.TBS.VerifyingKey = EntityPublicKey{
			Capabilities: []int{1, 2, 3},
			Key:          asn1.NewExternal(pk),
		}
		e.TBS.Validity.NotBefore = time.Now()
		e.TBS.Validity.NotAfter = time.Now().Add(5 * time.Hour)
		_, err := asn1.Marshal(e.TBS)
		require.NoError(b, err)
		e.Signature = []byte{55, 66, 77}
		wireEntity := WaveWireObject{
			Content: asn1.NewExternal(e),
		}
		_, err = asn1.Marshal(wireEntity.Content)
		require.NoError(b, err)
	}
}

func BenchmarkEntityDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		h := strings.Replace(entityHex, " ", "", -1)
		h = strings.Replace(h, "\n", "", -1)
		ba, err := hex.DecodeString(h)
		require.NoError(b, err)

		v := WaveWireObject{}
		rest, err := asn1.Unmarshal(ba, &v.Content)
		require.NoError(b, err)
		_ = rest
		_ = v
	}
}

func BenchmarkAttestationDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		h := strings.Replace(attestationHex, " ", "", -1)
		h = strings.Replace(h, "\n", "", -1)
		ba, err := hex.DecodeString(h)
		require.NoError(b, err)
		wo := WaveWireObject{}
		_, err = asn1.Unmarshal(ba, &wo.Content)
		require.NoError(b, err)
	}
}

func BenchmarkAttestationEncode(bm *testing.B) {
	for i := 0; i < bm.N; i++ {
		a := WaveAttestation{}
		subject := Keccak_256("hello")
		a.TBS.Subject = asn1.NewExternal(subject)

		b := AttestationBody{}
		b.VerifierBody.Attester = asn1.NewExternal(Keccak_256("world"))
		b.VerifierBody.Policy = asn1.NewExternal(TrustLevel{3})
		b.VerifierBody.Subject = asn1.NewExternal(subject)
		b.VerifierBody.Validity.NotAfter = time.Now().Add(50 * time.Minute)
		b.VerifierBody.Validity.NotBefore = time.Now()
		//b.ProverPolicyAddendums = append(b.ProverPolicyAddendums, asn1.NewExternal(WR1PartitionKey_OAQUE_BN256_s20("hello")))
		sigok := SignedOuterKey{}
		sigok.TBS.OuterSignatureScheme = EphemeralEd25519OID
		sigok.TBS.VerifyingKey = []byte("hello")
		sigok.Signature = []byte("foobar")
		b.VerifierBody.OuterSignatureBinding = asn1.NewExternal(sigok)
		outersig := Ed25519OuterSignature{}
		outersig.VerifyingKey = []byte("fhelllo")
		outersig.Signature = []byte("haai")
		a.TBS.Body = asn1.NewExternal(b)
		a.OuterSignature = asn1.NewExternal(outersig)

		wireEntity := WaveWireObject{
			Content: asn1.NewExternal(a),
		}
		_, err := asn1.Marshal(wireEntity.Content)
		require.NoError(bm, err)
	}
}
