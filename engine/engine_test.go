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

func TestNameDeclNoEncryption(t *testing.T) {
	ctx := context.Background()
	a, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	b, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})

	rv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:         a.EntitySecrets,
		AttesterLocation: inmem,
		Subject:          b.Entity,
		SubjectLocation:  inmem,
		Name:             "foo",
	})
	require.NoError(t, werr)
	ndhash, err := iapi.SI().PutNameDeclaration(ctx, inmem, rv.NameDeclaration)
	require.NoError(t, err)
	iapi.SI().PutEntity(ctx, inmem, a.Entity)
	iapi.SI().PutEntity(ctx, inmem, b.Entity)
	err = iapi.SI().Enqueue(ctx, inmem, a.Entity.Keccak256HI(), ndhash)
	require.NoError(t, err)

	eng, err := NewEngine(ctx, ws, iapi.SI(), b.EntitySecrets, inmem)
	require.NoError(t, err)
	err = eng.MarkEntityInterestingAndQueueForSync(a.Entity, inmem)
	require.NoError(t, err)
	err = eng.ResyncEntireGraph(ctx)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	lrv, err := eng.LookupName(ctx, a.Entity.Keccak256HI(), "foo")
	require.NoError(t, err)
	require.NotNil(t, lrv)
	require.EqualValues(t, lrv.Name, "foo")
	lrv, err = eng.LookupName(ctx, a.Entity.Keccak256HI(), "bar")
	require.NoError(t, err)
	require.Nil(t, lrv)
}

func TestNameDeclOneHop(t *testing.T) {
	ctx := context.Background()
	a, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	b, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	ns, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})

	rv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          a.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           b.Entity,
		SubjectLocation:   inmem,
		Name:              "foo",
		Namespace:         ns.Entity,
		NamespaceLocation: inmem,
		Partition:         iapi.Partition("p1", "p2"),
	})
	require.NoError(t, werr)
	ndhash, err := iapi.SI().PutNameDeclaration(ctx, inmem, rv.NameDeclaration)
	require.NoError(t, err)

	iapi.SI().PutEntity(ctx, inmem, a.Entity)
	iapi.SI().PutEntity(ctx, inmem, b.Entity)
	iapi.SI().PutEntity(ctx, inmem, ns.Entity)
	err = iapi.SI().Enqueue(ctx, inmem, a.Entity.Keccak256HI(), ndhash)
	require.NoError(t, err)

	nsex := ns.Entity.Keccak256HI().CanonicalForm()
	//Grant attestation from NS giving permission to read
	policy := serdes.RTreePolicy{
		Namespace:    *nsex,
		Indirections: 2,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *nsex,
				Permissions:   []string{"foo"},
				Resource:      "foo/bar",
			},
		},
	}
	pol, uerr := iapi.NewRTreePolicyScheme(policy, iapi.Partition("p1", "p2"))
	require.NoError(t, uerr)
	bodyscheme := &iapi.WR1BodyScheme{}
	arv, werr := iapi.NewParsedAttestation(ctx, &iapi.PCreateAttestation{
		Policy:            pol,
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          ns.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           b.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, werr)
	atthash, err := iapi.SI().PutAttestation(ctx, inmem, arv.Attestation)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(ctx, inmem, b.Entity.Keccak256HI(), atthash)
	require.NoError(t, err)
	eng, err := NewEngine(ctx, ws, iapi.SI(), b.EntitySecrets, inmem)
	require.NoError(t, err)
	err = eng.MarkEntityInterestingAndQueueForSync(a.Entity, inmem)
	require.NoError(t, err)
	err = eng.ResyncEntireGraph(ctx)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}

	lookup, val, err := eng.LookupAttestationInPerspective(ctx, atthash, inmem)
	require.NoError(t, err)
	require.NotNil(t, lookup)
	require.NotNil(t, lookup.DecryptedBody)
	require.True(t, val.Valid)
	lrv, err := eng.LookupName(ctx, a.Entity.Keccak256HI(), "foo")
	require.NoError(t, err)
	require.NotNil(t, lrv)
	require.EqualValues(t, lrv.Name, "foo")
	lrv, err = eng.LookupName(ctx, a.Entity.Keccak256HI(), "bar")
	require.NoError(t, err)
	require.Nil(t, lrv)
}

func TestNameDeclOneHopThroughLabelled(t *testing.T) {
	ctx := context.Background()
	a, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	b, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	ns, _ := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	fmt.Printf("NS is %x\n", ns.Entity.Keccak256())
	fmt.Printf("B  is %x\n", b.Entity.Keccak256())
	fmt.Printf("A  is %x\n", a.Entity.Keccak256())
	rv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          a.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           b.Entity,
		SubjectLocation:   inmem,
		Name:              "foo",
		Namespace:         ns.Entity,
		NamespaceLocation: inmem,
		Partition:         iapi.Partition("p1", "p2"),
	})
	require.NoError(t, werr)
	ndhash, err := iapi.SI().PutNameDeclaration(ctx, inmem, rv.NameDeclaration)
	require.NoError(t, err)

	iapi.SI().PutEntity(ctx, inmem, a.Entity)
	iapi.SI().PutEntity(ctx, inmem, b.Entity)
	iapi.SI().PutEntity(ctx, inmem, ns.Entity)
	err = iapi.SI().Enqueue(ctx, inmem, a.Entity.Keccak256HI(), ndhash)
	require.NoError(t, err)

	nsex := ns.Entity.Keccak256HI().CanonicalForm()
	//Grant attestation from NS giving permission to read
	policy := serdes.RTreePolicy{
		Namespace:    *nsex,
		Indirections: 2,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *nsex,
				Permissions:   []string{"foo"},
				Resource:      "foo/bar",
			},
		},
	}
	pol, uerr := iapi.NewRTreePolicyScheme(policy, iapi.Partition("p1", "p2", "p3")) //Too precise
	require.NoError(t, uerr)
	bodyscheme := &iapi.WR1BodyScheme{}
	arv, werr := iapi.NewParsedAttestation(ctx, &iapi.PCreateAttestation{
		Policy:            pol,
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          ns.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           b.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, werr)
	atthash, err := iapi.SI().PutAttestation(ctx, inmem, arv.Attestation)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(ctx, inmem, b.Entity.Keccak256HI(), atthash)
	require.NoError(t, err)
	eng, err := NewEngine(ctx, ws, iapi.SI(), b.EntitySecrets, inmem)
	require.NoError(t, err)
	err = eng.MarkEntityInterestingAndQueueForSync(a.Entity, inmem)
	require.NoError(t, err)
	err = eng.ResyncEntireGraph(ctx)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	lrv, err := eng.LookupName(ctx, a.Entity.Keccak256HI(), "foo")
	require.NoError(t, err)
	require.Nil(t, lrv)

	//Now add attestation with the right perspective
	pol, uerr = iapi.NewRTreePolicyScheme(policy, iapi.Partition("p1", "p2"))
	require.NoError(t, uerr)
	arv, werr = iapi.NewParsedAttestation(ctx, &iapi.PCreateAttestation{
		Policy:            pol,
		HashScheme:        &iapi.HashScheme_Keccak_256{},
		BodyScheme:        bodyscheme,
		EncryptionContext: nil,
		Attester:          ns.EntitySecrets,
		AttesterLocation:  inmem,
		Subject:           b.Entity,
		SubjectLocation:   inmem,
	})
	require.NoError(t, werr)
	atthash, err = iapi.SI().PutAttestation(ctx, inmem, arv.Attestation)
	require.NoError(t, err)
	err = iapi.SI().Enqueue(ctx, inmem, b.Entity.Keccak256HI(), atthash)
	require.NoError(t, err)
	fmt.Printf("- doing second resync\n")
	//eng.MarkEntityInterestingAndQueueForSync(ns.Entity, inmem)
	err = eng.ResyncEntireGraph(ctx)
	require.NoError(t, err)
	select {
	case <-eng.WaitForEmptySyncQueue():
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for empty sync")
	}
	time.Sleep(2 * time.Second)
	lrv, err = eng.LookupName(ctx, a.Entity.Keccak256HI(), "foo")
	require.NoError(t, err)
	require.NotNil(t, lrv)
	require.EqualValues(t, lrv.Name, "foo")

	lrv, err = eng.LookupName(ctx, a.Entity.Keccak256HI(), "bar")
	require.NoError(t, err)
	require.Nil(t, lrv)
}

func TestAttestationOneHop(t *testing.T) {
	ctx := context.Background()
	src, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	dst, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	//Create the attestation
	pol, uerr := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, uerr)
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
	require.NoError(t, err)
	atthash, uerr := iapi.SI().PutAttestation(context.Background(), inmem, readback.Attestation)
	require.NoError(t, uerr)
	_, uerr = iapi.SI().PutEntity(context.Background(), inmem, src.EntitySecrets.Entity)
	require.NoError(t, uerr)
	_, uerr = iapi.SI().PutEntity(context.Background(), inmem, dst.EntitySecrets.Entity)
	require.NoError(t, uerr)
	uerr = iapi.SI().Enqueue(context.Background(), inmem, dst.EntitySecrets.Entity.Keccak256HI(), atthash)
	require.NoError(t, uerr)

	eng, uerr := NewEngine(ctx, ws, iapi.SI(), dst.EntitySecrets, inmem)
	require.NoError(t, uerr)
	uerr = eng.ResyncEntireGraph(ctx)
	require.NoError(t, uerr)
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
	A, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	B, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	C, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	//Create the attestation from A to B
	pol, uerr := iapi.NewTrustLevelPolicy(3)
	require.NoError(t, uerr)
	bodyscheme := &iapi.WR1BodyScheme{}
	rv, werr := iapi.CreateAttestation(context.Background(), &iapi.PCreateAttestation{
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
	require.NoError(t, werr)
	readbackAB, werr := iapi.ParseAttestation(context.Background(), &iapi.PParseAttestation{
		DER: rv.DER,
	})
	require.NoError(t, werr)
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
	hashBC, uerr := iapi.SI().PutAttestation(context.Background(), inmem, readbackBC.Attestation)
	require.NoError(t, uerr)

	_, uerr = iapi.SI().PutEntity(context.Background(), inmem, A.EntitySecrets.Entity)
	require.NoError(t, uerr)
	_, uerr = iapi.SI().PutEntity(context.Background(), inmem, B.EntitySecrets.Entity)
	require.NoError(t, uerr)
	_, uerr = iapi.SI().PutEntity(context.Background(), inmem, C.EntitySecrets.Entity)
	require.NoError(t, uerr)
	uerr = iapi.SI().Enqueue(context.Background(), inmem, B.EntitySecrets.Entity.Keccak256HI(), hashAB)
	require.NoError(t, uerr)
	uerr = iapi.SI().Enqueue(context.Background(), inmem, C.EntitySecrets.Entity.Keccak256HI(), hashBC)
	require.NoError(t, uerr)

	eng, err := NewEngine(ctx, ws, iapi.SI(), C.EntitySecrets, inmem)
	require.NoError(t, err)
	uerr = eng.ResyncEntireGraph(ctx)
	require.NoError(t, uerr)
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
	A, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	B, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	C, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	NS, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	//Create the attestation from A to B
	sdpol := serdes.RTreePolicy{}
	nsh := NS.EntitySecrets.Entity.Keccak256HI().CanonicalForm()
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
	uerr := eng.ResyncEntireGraph(ctx)
	require.NoError(t, uerr)
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
	A, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	B, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)
	C, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	NS, werr := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, werr)

	//Create the attestation from A to B
	sdpol := serdes.RTreePolicy{}
	nsh := NS.EntitySecrets.Entity.Keccak256HI().CanonicalForm()
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
	uerr := eng.ResyncEntireGraph(ctx)
	require.NoError(t, uerr)
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
