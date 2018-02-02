package iapi

import "github.com/immesys/wave/serdes"

type Entity struct {
	canonicalForm *serdes.WaveEntity
	verifyingKey  EntityKeyScheme
	keys          []EntityKeyScheme
	revocations   []RevocationScheme
	extensions    []ExtensionScheme
}
type EntitySecrets struct {
	canonicalForm *serdes.WaveEntitySecret
	keyring       []EntitySecretKeyScheme
}
