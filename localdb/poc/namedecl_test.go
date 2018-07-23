package poc

import (
	"context"
	"testing"

	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/iapi"
	"github.com/stretchr/testify/require"
)

type Common struct {
	NS          *iapi.EntitySecrets
	NSLoc       iapi.LocationSchemeInstance
	Persp       *iapi.EntitySecrets
	Target      *iapi.EntitySecrets
	TargetLoc   iapi.LocationSchemeInstance
	Attester    *iapi.EntitySecrets
	AttesterLoc iapi.LocationSchemeInstance
	KPDC        *iapi.KeyPoolDecryptionContext
}

func common(t *testing.T) (context.Context, *Common) {
	ctx := context.Background()

	rv := &Common{}
	nsrv, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	rv.NS = nsrv.EntitySecrets
	trv, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	rv.Target = trv.EntitySecrets
	arv, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	rv.Attester = arv.EntitySecrets
	prv, err := iapi.NewParsedEntitySecrets(ctx, &iapi.PNewEntity{})
	require.NoError(t, err)
	rv.Persp = prv.EntitySecrets
	rv.NSLoc = iapi.NewLocationSchemeInstanceURL("https://test.com", 1)
	rv.TargetLoc = rv.NSLoc
	rv.AttesterLoc = rv.NSLoc
	rv.KPDC = iapi.NewKeyPoolDecryptionContext()
	ctx = context.WithValue(ctx, consts.PerspectiveKey, rv.Persp)
	return ctx, rv
}

func TestNameDeclPutGetPending(t *testing.T) {
	ctx, c := common(t)
	ndrv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          c.Attester,
		AttesterLocation:  c.AttesterLoc,
		Subject:           c.Target.Entity,
		SubjectLocation:   c.TargetLoc,
		Name:              "foo",
		Namespace:         c.NS.Entity,
		NamespaceLocation: c.NSLoc,
		Partition:         iapi.Partition("foo", "bar"),
	})
	require.NoError(t, werr)
	//Allow parse to verify attester signature
	c.KPDC.AddEntity(c.Attester.Entity)

	//We need to try parse the ND so the WR1Extra field gets populated
	parserv, werr := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
		DER:  ndrv.DER,
		Dctx: c.KPDC,
	})
	require.NoError(t, werr)

	nd := parserv.Result

	err := db.MoveNameDeclarationPendingP(ctx, nd, 1)
	require.NoError(t, err)

	//Try get it by namespace
	h := keccakFromHI(nd.Keccak256HI())
	rvc := db.GetPendingNameDeclarationP(ctx, c.NS.Entity.Keccak256HI(), 2)
	count := 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.Keccak256, h)
		count += 1
	}
	require.EqualValues(t, count, 1)
}

func TestNameDeclPutGetLabelled(t *testing.T) {
	ctx, c := common(t)
	ndrv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          c.Attester,
		AttesterLocation:  c.AttesterLoc,
		Subject:           c.Target.Entity,
		SubjectLocation:   c.TargetLoc,
		Name:              "foo",
		Namespace:         c.NS.Entity,
		NamespaceLocation: c.NSLoc,
		Partition:         iapi.Partition("foo", "bar"),
	})
	require.NoError(t, werr)
	//Allow parse to verify attester signature
	c.KPDC.AddEntity(c.Attester.Entity)
	//And allow it to decrypt the label
	c.KPDC.AddEntitySecretsLabelOnly(c.NS)
	c.KPDC.AddDomainVisibilityID([]byte(c.NS.Entity.Keccak256HI().MultihashString()))

	//We need to try parse the ND so the WR1Extra field gets populated
	parserv, werr := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
		DER:  ndrv.DER,
		Dctx: c.KPDC,
	})
	require.NoError(t, werr)

	nd := parserv.Result

	err := db.MoveNameDeclarationPendingP(ctx, nd, 1)
	require.NoError(t, err)
	err = db.MoveNameDeclarationLabelledP(ctx, nd)
	require.NoError(t, err)

	//Try get it by namespace
	h := keccakFromHI(nd.Keccak256HI())
	rvc := db.GetLabelledNameDeclarationsP(ctx, c.NS.Entity.Keccak256HI(), iapi.Partition20("foo", "bar"))
	count := 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.Keccak256, h)
		count += 1
	}
	require.EqualValues(t, count, 1)
}

func TestNameDeclPutGetActiveEncrypted(t *testing.T) {
	ctx, c := common(t)
	ndrv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:          c.Attester,
		AttesterLocation:  c.AttesterLoc,
		Subject:           c.Target.Entity,
		SubjectLocation:   c.TargetLoc,
		Name:              "foo",
		Namespace:         c.NS.Entity,
		NamespaceLocation: c.NSLoc,
		Partition:         iapi.Partition("foo", "bar"),
	})
	require.NoError(t, werr)
	//Allow parse to verify attester signature
	c.KPDC.AddEntity(c.Attester.Entity)
	//And allow it to decrypt the label
	c.KPDC.AddEntitySecret(c.NS, true)
	c.KPDC.AddDomainVisibilityID([]byte(c.NS.Entity.Keccak256HI().MultihashString()))

	//We need to try parse the ND so the WR1Extra field gets populated
	parserv, werr := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
		DER:  ndrv.DER,
		Dctx: c.KPDC,
	})
	require.NoError(t, werr)

	nd := parserv.Result
	require.True(t, nd.Decoded())
	err := db.MoveNameDeclarationActiveP(ctx, nd)
	require.NoError(t, err)

	h := keccakFromHI(nd.Keccak256HI())
	rvc := db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "foo")
	count := 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 1)

	rvc = db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "bar")
	count = 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 0)

	err = db.MoveNameDeclarationExpiredP(ctx, nd)
	require.NoError(t, err)

	rvc = db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "foo")
	count = 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 0)

}

func TestNameDeclPutGetActiveNotEncrypted(t *testing.T) {
	ctx, c := common(t)
	ndrv, werr := iapi.CreateNameDeclaration(ctx, &iapi.PCreateNameDeclaration{
		Attester:         c.Attester,
		AttesterLocation: c.AttesterLoc,
		Subject:          c.Target.Entity,
		SubjectLocation:  c.TargetLoc,
		Name:             "foo",
	})
	require.NoError(t, werr)
	//Allow parse to verify attester signature
	c.KPDC.AddEntity(c.Attester.Entity)

	//We need to try parse the ND so the WR1Extra field gets populated
	parserv, werr := iapi.ParseNameDeclaration(ctx, &iapi.PParseNameDeclaration{
		DER:  ndrv.DER,
		Dctx: c.KPDC,
	})
	require.NoError(t, werr)

	nd := parserv.Result
	require.True(t, nd.Decoded())
	err := db.MoveNameDeclarationActiveP(ctx, nd)
	require.NoError(t, err)

	h := keccakFromHI(nd.Keccak256HI())
	rvc := db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "foo")
	count := 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 1)

	rvc = db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "bar")
	count = 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 0)

	err = db.MoveNameDeclarationRevokedP(ctx, nd)
	require.NoError(t, err)

	rvc = db.ResolveNameDeclarationsP(ctx, c.Attester.Entity.Keccak256HI(), "foo")
	count = 0
	for e := range rvc {
		require.NoError(t, e.Err)
		require.Equal(t, e.NameDeclaration.Keccak256(), h)
		count += 1
	}
	require.EqualValues(t, count, 0)

}
