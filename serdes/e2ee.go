package serdes

import "github.com/immesys/asn1"

type WaveEncryptedMessage struct {
	Contents   []byte
	Keys       []asn1.External
	Extensions []Extension
}
type MessageKeyCurve25519ECDH struct {
	Ciphertext []byte
}

type MessageKeyWR1 struct {
	Envelope            []byte
	EnvelopeKeyIBEBN256 []byte
	Namespace           asn1.External
	NamespaceLocation   asn1.External
}

type MessageKeyWR1Envelope struct {
	Partition   [][]byte
	ContentsKey []byte
}
