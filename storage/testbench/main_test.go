package testbench

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	"github.com/immesys/wave/storage/simplehttp"
	"github.com/stretchr/testify/require"
)

//Modify this to instantiate the storage provider you want to test:
func getInstance(t *testing.T) iapi.StorageDriverInterface {
	return getSimpleHTTPStorageInstance(t)
}

func getSimpleHTTPStorageInstance(t *testing.T) iapi.StorageDriverInterface {
	sh := &simplehttp.SimpleHTTPStorage{}
	cfg := make(map[string]string)
	//cfg["url"] = "http://vldm.cal-sdb.org:8080/v1"
	//	cfg["v1key"] = `-----BEGIN PUBLIC KEY-----
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJeCG0aGGL93ZisvIih7ZVRVPdUis
	//gImCbKUF6SvULO1DxQUjH+zF4+AO4R0yX6rYKPZ1D10VZ055tG3oEIK3hQ==
	//-----END PUBLIC KEY-----`
	cfg["url"] = "https://standalone.storage.bwave.io/v1"
	require.NoError(t, sh.Initialize(context.Background(), "simplehttp", cfg))
	return sh
}

func init() {
	go memoryserver.Main()
	time.Sleep(100 * time.Millisecond)
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	ov, err := overlay.NewOverlay(cfg)
	if err != nil {
		panic(err)
	}
	iapi.InjectStorageInterface(ov)
}
func TestXPutGetAttestation(t *testing.T) {
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	inmem := iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	ov, err := overlay.NewOverlay(cfg)
	require.NoError(t, err)

	source, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, werr)
	dst, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, werr)
	pol, err := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := iapi.NewPlaintextBodyScheme()
	rv, err := iapi.NewParsedAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy:            pol,
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          source.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           dst.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	ctx := context.Background()
	require.NoError(t, err)
	hi, err := ov.PutAttestation(ctx, inmem, rv.Attestation)
	require.NoError(t, err)

	att, err := ov.GetAttestation(ctx, inmem, hi)
	require.NoError(t, err)
	require.NotNil(t, att)

	other, err := ov.GetAttestationOrDeclaration(ctx, inmem, hi)
	require.NoError(t, err)
	require.Nil(t, other.NameDeclaration)
	require.NotNil(t, other.Attestation)
}

func TestXPutGetNameDeclaration(t *testing.T) {
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	inmem := iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	ov, err := overlay.NewOverlay(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	source, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, werr)
	dst, werr := iapi.NewParsedEntitySecrets(context.Background(), &iapi.PNewEntity{})
	require.NoError(t, werr)

	rv, err := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          source.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           dst.Entity,
		SubjectLocation:   inmem,
		Name:              "foo",
		Namespace:         source.Entity,
		NamespaceLocation: inmem,
		Partition:         [][]byte{[]byte("foo")},
	})
	hi, err := ov.PutNameDeclaration(ctx, inmem, rv.NameDeclaration)
	require.NoError(t, err)
	other, err := ov.GetAttestationOrDeclaration(ctx, inmem, hi)
	require.NoError(t, err)
	require.NotNil(t, other.NameDeclaration)
	require.Nil(t, other.Attestation)
}

func TestPutGet(t *testing.T) {
	in := getInstance(t)
	//This has no perspective entity, probably not a problem for now
	ctx := context.Background()
	//About the size of an attestation
	content := make([]byte, 80)
	rand.Read(content)

	hi, err := in.Put(ctx, content)
	require.NoError(t, err)

	readback, err := in.Get(ctx, hi)
	require.NoError(t, err)
	require.EqualValues(t, content, readback)
}

func TestPutGetDelay(t *testing.T) {
	in := getInstance(t)
	//This has no perspective entity, probably not a problem for now
	ctx := context.Background()
	//About the size of an attestation
	content := make([]byte, 80)
	rand.Read(content)

	hi, err := in.Put(ctx, content)
	require.NoError(t, err)
	time.Sleep(10 * time.Second)
	readback, err := in.Get(ctx, hi)
	require.NoError(t, err)
	require.EqualValues(t, content, readback)
}

func TestEnqueDequeue(t *testing.T) {
	in := getInstance(t)
	//This has no perspective entity, probably not a problem for now
	ctx := context.Background()
	//About the size of an attestation
	content := make([]byte, 80)
	rand.Read(content)
	hi, err := in.Put(ctx, content)
	require.NoError(t, err)

	//Put another one in case the provider only allows queues for extant objects
	content2 := make([]byte, 80)
	rand.Read(content2)
	hi2, err := in.Put(ctx, content2)
	require.NoError(t, err)
	content3 := make([]byte, 80)
	rand.Read(content3)
	hi3, err := in.Put(ctx, content3)
	require.NoError(t, err)

	err = in.Enqueue(ctx, hi, hi2)
	require.NoError(t, err)
	err = in.Enqueue(ctx, hi, hi3)
	require.NoError(t, err)

	rb2, nxt, err := in.IterateQueue(ctx, hi, "")
	require.NoError(t, err)
	require.EqualValues(t, hi2, rb2)
	rb3, nxt, err := in.IterateQueue(ctx, hi, nxt)
	require.NoError(t, err)
	require.EqualValues(t, rb3, hi3)
	rb4, _, err := in.IterateQueue(ctx, hi, nxt)
	require.Equal(t, iapi.ErrNoMore, err)
	require.Nil(t, rb4)
}

func TestEnqueDequeueDelay(t *testing.T) {
	in := getInstance(t)
	//This has no perspective entity, probably not a problem for now
	ctx := context.Background()
	//About the size of an attestation
	content := make([]byte, 80)
	rand.Read(content)
	hi, err := in.Put(ctx, content)
	require.NoError(t, err)

	//Put another one in case the provider only allows queues for extant objects
	content2 := make([]byte, 80)
	rand.Read(content2)
	hi2, err := in.Put(ctx, content2)
	require.NoError(t, err)
	content3 := make([]byte, 80)
	rand.Read(content3)
	hi3, err := in.Put(ctx, content3)
	require.NoError(t, err)

	err = in.Enqueue(ctx, hi, hi2)
	require.NoError(t, err)
	err = in.Enqueue(ctx, hi, hi3)
	require.NoError(t, err)

	time.Sleep(10 * time.Second)

	rb2, nxt, err := in.IterateQueue(ctx, hi, "")
	require.NoError(t, err)
	require.EqualValues(t, hi2, rb2)
	rb3, nxt, err := in.IterateQueue(ctx, hi, nxt)
	require.NoError(t, err)
	require.EqualValues(t, rb3, hi3)
	rb4, _, err := in.IterateQueue(ctx, hi, nxt)
	require.Equal(t, iapi.ErrNoMore, err)
	require.Nil(t, rb4)
}

func BenchmarkPut2KB(b *testing.B) {
	body := make([]byte, 2000)
	in := getInstance(nil)
	rand.Read(body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(body[0:8], uint64(i))
		in.Put(context.Background(), body)
	}
}

func BenchmarkGet2KB(b *testing.B) {
	body := make([]byte, 2000)
	in := getInstance(nil)
	rand.Read(body)
	resp, _ := in.Put(context.Background(), body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Get(context.Background(), resp)
	}
}

func BenchmarkGet2KBDelay(b *testing.B) {
	body := make([]byte, 2000)
	in := getInstance(nil)
	rand.Read(body)
	resp, _ := in.Put(context.Background(), body)
	time.Sleep(5 * time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Get(context.Background(), resp)
	}
}

func BenchmarkEnqueue(b *testing.B) {
	qid := make([]byte, 53)
	rand.Read(qid)
	hash := iapi.KECCAK256.Instance(qid)
	other := make([]byte, 32)
	rand.Read(other)
	valhash := iapi.KECCAK256.Instance(other)
	in := getInstance(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Enqueue(context.Background(), hash, valhash)
	}
}

func BenchmarkDequeue(b *testing.B) {
	qid := make([]byte, 53)
	rand.Read(qid)
	hash := iapi.KECCAK256.Instance(qid)
	other := make([]byte, 32)
	rand.Read(other)
	valhash := iapi.KECCAK256.Instance(other)
	in := getInstance(nil)
	in.Enqueue(context.Background(), hash, valhash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.IterateQueue(context.Background(), hash, "")
	}
}
