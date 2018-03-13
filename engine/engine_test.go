package engine

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/storage/memoryserver"
	"github.com/immesys/wave/storage/overlay"
	"github.com/stretchr/testify/require"
)

var ws iapi.WaveState
var inmem iapi.LocationSchemeInstance

func init() {
	//Do the storage
	go memoryserver.Main()
	time.Sleep(100 * time.Millisecond)
	cfg := make(map[string]map[string]string)
	cfg["inmem"] = make(map[string]string)
	cfg["inmem"]["provider"] = "http_v1"
	cfg["inmem"]["url"] = "http://localhost:8080/v1"
	inmem = iapi.NewLocationSchemeInstanceURL(cfg["inmem"]["url"], 1)
	si, err := overlay.NewOverlay(cfg)
	if err != nil {
		panic(err)
	}
	iapi.InjectStorageInterface(si)
	//Do the wave state
	tdir, _ := ioutil.TempDir("", "lls")
	llsdb, err := lls.NewLowLevelStorage(tdir)
	if err != nil {
		panic(err)
	}
	ws = poc.NewPOC(llsdb)
}

func TestAttestationOneHop(t *testing.T) {
	ctx := context.Background()
	src, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	dst, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	//Create the attestation
	pol, err := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, err := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          src.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           dst.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)

	readback, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	atthash, err := iapi.SI().PutAttestation(context.Background(), inmem, readback.Attestation)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, src.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, dst.EntitySecrets.Entity)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, dst.EntitySecrets.Entity.Keccak256HI(), atthash)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), dst.EntitySecrets, inmem)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	clr, cerr := eng.LookupAttestationsFrom(ctx, src.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count := 0
loop:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop
		}
	}
	require.EqualValues(t, 1, count)
}

func TestAttestationTwoHop(t *testing.T) {
	ctx := context.Background()
	A, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	B, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	C, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	//Create the attestation from A to B
	pol, err := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, err)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, err := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          A.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           B.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackAB, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashAB, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackAB.Attestation)
	require.NoError(t, err)

	//BC
	rv, err = iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          B.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           C.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackBC, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashBC, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackBC.Attestation)
	require.NoError(t, err)

	_, err = iapi.SI().PutEntity(context.Background(), inmem, A.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, B.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, C.EntitySecrets.Entity)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, B.EntitySecrets.Entity.Keccak256HI(), hashAB)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, C.EntitySecrets.Entity.Keccak256HI(), hashBC)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), C.EntitySecrets, inmem)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	clr, cerr := eng.LookupAttestationsFrom(ctx, B.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count := 0
loop1:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop1
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop1
		}
	}
	require.EqualValues(t, 1, count)

	clr, cerr = eng.LookupAttestationsFrom(ctx, A.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count = 0
loop2:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop2
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop2
		}
	}
	require.EqualValues(t, 1, count)
}

func TestAttestationTwoHopRTree(t *testing.T) {
	ctx := context.Background()
	A, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	B, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	C, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	NS, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	//Create the attestation from A to B
	sdpol := serdes.RTreePolicy{}
	nsh, err := NS.EntitySecrets.Entity.Keccak256HI().CanonicalForm()
	require.NoError(t, err)
	sdpol.Namespace = *nsh
	sdpol.Indirections = 5
	sdpol.Statements = append(sdpol.Statements, serdes.RTreeStatement{
		PermissionSet: *nsh,
		Permissions:   []string{"foo"},
		Resource:      "foo/bar",
	})
	pol, err := iapi.NewRTreePolicyScheme(sdpol, [][]byte{[]byte("hello"), []byte("world")})
	require.NoError(t, err)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, err := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          A.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           B.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackAB, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashAB, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackAB.Attestation)
	require.NoError(t, err)

	//BC
	polbc, err := iapi.NewRTreePolicyScheme(sdpol, [][]byte{[]byte("hello")})
	rv, err = iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: polbc,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          B.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           C.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackBC, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashBC, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackBC.Attestation)
	require.NoError(t, err)

	_, err = iapi.SI().PutEntity(context.Background(), inmem, A.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, B.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, C.EntitySecrets.Entity)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, B.EntitySecrets.Entity.Keccak256HI(), hashAB)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, C.EntitySecrets.Entity.Keccak256HI(), hashBC)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), C.EntitySecrets, inmem)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	clr, cerr := eng.LookupAttestationsFrom(ctx, B.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count := 0
loop1:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop1
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop1
		}
	}
	require.EqualValues(t, 1, count)

	clr, cerr = eng.LookupAttestationsFrom(ctx, A.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count = 0
loop2:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop2
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop2
		}
	}
	require.EqualValues(t, 1, count)
}

func TestAttestationTwoHopRTreeNoVis(t *testing.T) {
	ctx := context.Background()
	A, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	B, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	C, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	NS, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)

	//Create the attestation from A to B
	sdpol := serdes.RTreePolicy{}
	nsh, err := NS.EntitySecrets.Entity.Keccak256HI().CanonicalForm()
	require.NoError(t, err)
	sdpol.Namespace = *nsh
	sdpol.Indirections = 5
	sdpol.Statements = append(sdpol.Statements, serdes.RTreeStatement{
		PermissionSet: *nsh,
		Permissions:   []string{"foo"},
		Resource:      "foo/bar",
	})
	pol, err := iapi.NewRTreePolicyScheme(sdpol, [][]byte{[]byte("hello")})
	require.NoError(t, err)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, err := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: pol,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          A.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           B.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackAB, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashAB, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackAB.Attestation)
	require.NoError(t, err)

	//BC
	polbc, err := iapi.NewRTreePolicyScheme(sdpol, [][]byte{[]byte("hello"), []byte("world")})
	rv, err = iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
		Policy: polbc,
		//TODO test with this, it fails right now
		//HashScheme:        &HashScheme_Sha3_256{},
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          B.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           C.EntitySecrets.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, err)
	readbackBC, err := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	hashBC, err := iapi.SI().PutAttestation(context.Background(), inmem, readbackBC.Attestation)
	require.NoError(t, err)

	_, err = iapi.SI().PutEntity(context.Background(), inmem, A.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, B.EntitySecrets.Entity)
	require.NoError(t, err)
	_, err = iapi.SI().PutEntity(context.Background(), inmem, C.EntitySecrets.Entity)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, B.EntitySecrets.Entity.Keccak256HI(), hashAB)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(context.Background(), inmem, C.EntitySecrets.Entity.Keccak256HI(), hashBC)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), C.EntitySecrets, inmem)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	clr, cerr := eng.LookupAttestationsFrom(ctx, B.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count := 0
loop4:
	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop4
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop4
		}
	}
	require.EqualValues(t, 1, count)

	clr, cerr = eng.LookupAttestationsFrom(ctx, A.EntitySecrets.Entity.Keccak256HI(), &iapi.LookupFromFilter{})
	count = 0
loop5:

	for {
		select {
		case c, ok := <-clr:
			if !ok {
				break loop5
			}
			_ = c
			count++
			//spew.Dump(c)
		case e := <-cerr:
			fmt.Printf("got err %v\n", e)
			require.NoError(t, e)
			break loop5
		}
	}
	require.EqualValues(t, 0, count)
}
