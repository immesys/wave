package serdes

import (
	"time"

	"github.com/immesys/asn1"
)

type WaveNameDeclaration struct {
	TBS struct {
		Attester         asn1.External
		AttesterLocation asn1.External
		Revocations      []RevocationOption
		PublicExtensions []Extension
		Body             []byte
		Keys             []asn1.External
	}
	Signature []byte
}

type NameDeclarationBody struct {
	Name            string `asn1:"utf8"`
	Subject         asn1.External
	SubjectLocation asn1.External
	Validity        struct {
		NotBefore time.Time `asn1:"utc"`
		NotAfter  time.Time `asn1:"utc"`
	}
	PrivateExtensions []Extension
}

type NameDeclarationKeyNone struct {
}

type NameDeclarationKeyWR1 struct {
	Envelope          []byte
	EnvelopeKey       []byte
	Namespace         asn1.External
	NamespaceLocation asn1.External
}

type NameDeclarationWR1Envelope struct {
	Partition [][]byte
	BodyKey   []byte
}
