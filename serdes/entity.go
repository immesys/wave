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
