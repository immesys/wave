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
		Contact     string `asn1:"utf8,tag:0,optional,implicit"`
		Comment     string `asn1:"utf8,tag:1,optional,implicit"`
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
