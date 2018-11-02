package serdes

import (
	"time"

	"github.com/immesys/asn1"
)

type WaveEntity struct {
	TBS struct {
		Raw          asn1.RawContent
		VerifyingKey EntityPublicKey
		Keys         []EntityPublicKey
		Validity     struct {
			NotBefore time.Time `asn1:"utc"`
			NotAfter  time.Time `asn1:"utc"`
		}
		Revocations []RevocationOption
		Extensions  []Extension
	}
	Signature []byte
}

type EntityPublicKey struct {
	Capabilities []int `asn1:"set"`
	Key          asn1.External
}

type WaveEntitySecret struct {
	Entity  WaveEntity
	Keyring asn1.External
}

type EntityKeyring struct {
	Keys []EntityKeyringEntry
}

type EntityKeyringEntry struct {
	Public  EntityPublicKey
	Private asn1.External
}

type BLS12381OAQUEKeyringBundle struct {
	Params  EntityParamsOQAUE_BLS12381_s20
	Entries []BLS12381OAQUEKeyringBundleEntry
}

type BLS12381OAQUEKeyringBundleEntry struct {
	PartitionChange []PartitionChange
	Key             EntitySecretOQAUE_BLS12381_s20
}

type PartitionChange struct {
	Index   int
	Content []byte
}

type Signature struct {
	Scheme    asn1.ObjectIdentifier
	Signature []byte
}
