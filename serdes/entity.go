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
			NotBefore time.Time
			NotAfter  time.Time
		}
		Revocations []RevocationOption
		Extensions  []Extension
	}
	Signature []byte
}

type EntityPublicKey struct {
	Capabilities []int64 `asn1:"set"`
	Key          asn1.External
}
