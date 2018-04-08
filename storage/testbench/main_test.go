package testbench

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/immesys/wave/iapi"
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
	cfg["url"] = "http://localhost:8080/v1"
	require.NoError(t, sh.Initialize(context.Background(), "simplehttp", cfg))
	return sh
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
	require.EqualValues(t, rb2, hi2)
	rb3, nxt, err := in.IterateQueue(ctx, hi, nxt)
	require.NoError(t, err)
	require.EqualValues(t, rb3, hi3)
	rb4, _, err := in.IterateQueue(ctx, hi, nxt)
	require.Equal(t, iapi.ErrNoMore, err)
	require.Nil(t, rb4)

}
