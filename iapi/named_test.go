package iapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNamedNoDecrypt(t *testing.T) {
	//The namespace authority, also doing the naming
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	//The one learning the name
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	_ = dst
	//The one getting named
	target, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	ctx := context.Background()

	crv, err := CreateNameDeclaration(ctx, &PCreateNameDeclaration{
		Attester:          source.EntitySecrets,
		AttesterLocation:  NewLocationSchemeInstanceURL("test", 1),
		Subject:           target.Entity,
		SubjectLocation:   NewLocationSchemeInstanceURL("test", 1),
		Name:              "foo",
		Namespace:         source.Entity,
		NamespaceLocation: NewLocationSchemeInstanceURL("test", 1),
		Partition:         [][]byte{[]byte("foo")},
	})
	require.NoError(t, err)

	kpdc := NewKeyPoolDecryptionContext()
	kpdc.AddEntitySecret(source.EntitySecrets, true)

	prv, err := ParseNameDeclaration(ctx, &PParseNameDeclaration{
		DER:  crv.DER,
		Dctx: kpdc,
	})
	require.NoError(t, err)

	require.NotNil(t, prv.Result)
	require.False(t, prv.IsMalformed)
	require.Nil(t, prv.Result.DecryptedBody)
	require.False(t, prv.Result.Decoded())
	require.NotNil(t, prv.Result.CanonicalForm)
	require.NotNil(t, prv.Result.WR1Extra)
	require.NotNil(t, prv.Result.WR1Extra.Namespace)
	require.Equal(t, prv.Result.Attester.Multihash(), source.Entity.Keccak256HI().Multihash())
}

func TestNamedNoEncryption(t *testing.T) {
	//The namespace authority, also doing the naming
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	//The one learning the name
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	_ = dst
	//The one getting named
	target, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	ctx := context.Background()

	crv, err := CreateNameDeclaration(ctx, &PCreateNameDeclaration{
		Attester:         source.EntitySecrets,
		AttesterLocation: NewLocationSchemeInstanceURL("test", 1),
		Subject:          target.Entity,
		SubjectLocation:  NewLocationSchemeInstanceURL("test", 1),
		Name:             "foo",
	})
	require.NoError(t, err)

	kpdc := NewKeyPoolDecryptionContext()
	kpdc.AddEntity(source.Entity)

	prv, err := ParseNameDeclaration(ctx, &PParseNameDeclaration{
		DER:  crv.DER,
		Dctx: kpdc,
	})
	require.NoError(t, err)

	require.NotNil(t, prv.Result)
	require.False(t, prv.IsMalformed)
	require.NotNil(t, prv.Result.DecryptedBody)
	require.True(t, prv.Result.Decoded())
	require.NotNil(t, prv.Result.CanonicalForm)
	require.Nil(t, prv.Result.WR1Extra)
	//require.Nil(t, prv.Result.WR1Extra.Namespace)
	require.Equal(t, prv.Result.Attester.Multihash(), source.Entity.Keccak256HI().Multihash())
	require.Equal(t, prv.Result.Subject.Multihash(), target.Entity.Keccak256HI().Multihash())
	require.Equal(t, prv.Result.Name, "foo")
}

func TestNamedEncryption(t *testing.T) {
	//The namespace authority, also doing the naming
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	//The one learning the name
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	_ = dst
	//The one getting named
	target, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	ctx := context.Background()

	crv, err := CreateNameDeclaration(ctx, &PCreateNameDeclaration{
		Attester:          source.EntitySecrets,
		AttesterLocation:  NewLocationSchemeInstanceURL("test", 1),
		Subject:           target.Entity,
		SubjectLocation:   NewLocationSchemeInstanceURL("test", 1),
		Name:              "foo",
		Namespace:         source.Entity,
		NamespaceLocation: NewLocationSchemeInstanceURL("test", 1),
		Partition:         [][]byte{[]byte("bar")},
	})
	require.NoError(t, err)

	kpdc := NewKeyPoolDecryptionContext()
	kpdc.AddDomainVisibilityID([]byte(source.Entity.Keccak256HI().MultihashString()))
	kpdc.AddEntitySecret(source.EntitySecrets, true)

	prv, err := ParseNameDeclaration(ctx, &PParseNameDeclaration{
		DER:  crv.DER,
		Dctx: kpdc,
	})
	require.NoError(t, err)

	require.NotNil(t, prv.Result)
	require.False(t, prv.IsMalformed)
	require.NotNil(t, prv.Result.DecryptedBody)
	require.True(t, prv.Result.Decoded())
	require.NotNil(t, prv.Result.CanonicalForm)
	require.NotNil(t, prv.Result.WR1Extra)
	require.NotNil(t, prv.Result.WR1Extra.Partition)
	require.NotNil(t, prv.Result.WR1Extra.Namespace)
	require.Equal(t, prv.Result.Attester.Multihash(), source.Entity.Keccak256HI().Multihash())
	require.Equal(t, prv.Result.Subject.Multihash(), target.Entity.Keccak256HI().Multihash())
	require.Equal(t, prv.Result.Name, "foo")
}

func TestNamedEncryptionLabelOnly(t *testing.T) {
	//The namespace authority, also doing the naming
	source, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	//The one learning the name
	dst, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	_ = dst
	//The one getting named
	target, werr := NewParsedEntitySecrets(context.Background(), &PNewEntity{})
	require.NoError(t, werr)
	ctx := context.Background()

	crv, err := CreateNameDeclaration(ctx, &PCreateNameDeclaration{
		Attester:          source.EntitySecrets,
		AttesterLocation:  NewLocationSchemeInstanceURL("test", 1),
		Subject:           target.Entity,
		SubjectLocation:   NewLocationSchemeInstanceURL("test", 1),
		Name:              "foo",
		Namespace:         source.Entity,
		NamespaceLocation: NewLocationSchemeInstanceURL("test", 1),
		Partition:         [][]byte{[]byte("bar")},
	})
	require.NoError(t, err)

	kpdc := NewKeyPoolDecryptionContext()
	kpdc.AddDomainVisibilityID([]byte(source.Entity.Keccak256HI().MultihashString()))
	kpdc.AddEntitySecretsLabelOnly(source.EntitySecrets)

	prv, err := ParseNameDeclaration(ctx, &PParseNameDeclaration{
		DER:  crv.DER,
		Dctx: kpdc,
	})
	require.NoError(t, err)

	require.NotNil(t, prv.Result)
	require.False(t, prv.IsMalformed)
	require.Nil(t, prv.Result.DecryptedBody)
	require.False(t, prv.Result.Decoded())
	require.NotNil(t, prv.Result.CanonicalForm)
	require.NotNil(t, prv.Result.WR1Extra)
	require.NotNil(t, prv.Result.WR1Extra.Partition)
	require.NotNil(t, prv.Result.WR1Extra.Namespace)
}
