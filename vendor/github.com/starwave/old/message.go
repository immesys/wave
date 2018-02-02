package core

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"golang.org/x/crypto/nacl/secretbox"
	msgpack "gopkg.in/vmihailenco/msgpack.v2"
)

// StarWaveKey is an OAQUE key bundled with the URI and Path for which it is
// valid.
type StarWaveKey struct {
	Namespace string
	Key       *oaque.PrivateKey
	UriPath   URIPath
	TimePath  TimePath
}

func (swk StarWaveKey) Marshal() []byte {
	components := []interface{}{swk.Namespace, swk.Key.Marshal(), swk.UriPath, swk.TimePath}
	marshalled, err := msgpack.Marshal(components)
	if err != nil {
		panic(err)
	}
	return marshalled
}

func (swk StarWaveKey) Unmarshal(marshalled []byte) {
	components := []interface{}{nil, nil, nil, nil}
	err := msgpack.Unmarshal(marshalled, components)
	if err != nil {
		panic(err)
	}
	swk.Namespace = components[0].(string)
	var success bool
	swk.Key, success = new(oaque.PrivateKey).Unmarshal(components[1].([]byte))
	if !success {
		panic("Invalid private key")
	}
	swk.UriPath = components[2].(URIPath)
	swk.TimePath = components[3].(TimePath)
}

func (swk StarWaveKey) DecryptionKey(params *oaque.Params, uriPath URIPath, timePath TimePath) *oaque.PrivateKey {
	attrs := AttributeSetFromPaths(uriPath, timePath)
	subkey, err := oaque.QualifyKey(nil, params, swk.Key, attrs)
	if err != nil {
		panic(err)
	}
	return subkey
}

// StarWaveCiphertext is an OAQUE ciphertext bundled with the URI and path for
// which it is intended. The encrypted value is a 32-byte symmetric key.
type StarWaveCiphertext struct {
	Ciphertext *oaque.Ciphertext
	UriPath    URIPath
	TimePath   TimePath
}

func (swc StarWaveCiphertext) Marshal() []byte {
	components := []interface{}{swc.Ciphertext.Marshal(), swc.UriPath, swc.TimePath}
	marshalled, err := msgpack.Marshal(components)
	if err != nil {
		panic(err)
	}
	return marshalled
}

func (swc StarWaveCiphertext) Unmarshal(marshalled []byte) {
	components := []interface{}{nil, nil, nil}
	err := msgpack.Unmarshal(marshalled, components)
	if err != nil {
		panic(err)
	}
	var success bool
	swc.Ciphertext, success = new(oaque.Ciphertext).Unmarshal(components[0].([]byte))
	if !success {
		panic("Invalid private key")
	}
	swc.UriPath = components[1].(URIPath)
	swc.TimePath = components[2].(TimePath)
}

// GenerateSymmetricKey generates a 16-byte symmetric key. It returns the key
// itself, and the ciphertext of that key.
func GenerateSymmetricKey(namespace *oaque.Params, uriPath URIPath, timePath TimePath, sk []byte) ([]byte, StarWaveCiphertext) {
	attrs := AttributeSetFromPaths(uriPath, timePath)
	key, hashesToKey := cryptutils.GenerateKey(sk)
	ct, err := oaque.Encrypt(nil, namespace, attrs, hashesToKey)
	if err != nil {
		panic(err)
	}
	return key, StarWaveCiphertext{
		Ciphertext: ct,
		UriPath:    uriPath,
		TimePath:   timePath,
	}
}

// DecodeSymmetricKey decodes a 16-byte symmetric key, using a key with a
// superset of the necessary permissions.
func DecodeSymmetricKey(params *oaque.Params, key *oaque.PrivateKey, ciphertext StarWaveCiphertext, sk []byte) []byte {
	attrs := AttributeSetFromPaths(ciphertext.UriPath, ciphertext.TimePath)
	childKey, err := oaque.QualifyKey(nil, params, key, attrs)
	if err != nil {
		panic(err)
	}
	hashesToKey := oaque.Decrypt(childKey, ciphertext.Ciphertext)
	return cryptutils.GTToSecretKey(hashesToKey, sk)
}

type EncryptedSingleMessage struct {
	EncryptedKey     StarWaveCiphertext
	EncryptedMessage []byte
}

// EncryptSingle encrypts a single message using a unique symmetric key.
func EncryptSingle(params *oaque.Params, uriPath URIPath, timePath TimePath, message []byte) EncryptedSingleMessage {
	var key [32]byte
	_, encryptedKey := GenerateSymmetricKey(params, uriPath, timePath, key[:])

	var nonce [24]byte
	output := make([]byte, len(message)+secretbox.Overhead)
	secretbox.Seal(output, message, &nonce, &key)

	return EncryptedSingleMessage{
		EncryptedKey:     encryptedKey,
		EncryptedMessage: output,
	}
}

// DecryptSingle decrypts a message encrypted with a unique symmetric key.
func DecryptSingle(params *oaque.Params, key *oaque.PrivateKey, encrypted EncryptedSingleMessage) ([]byte, bool) {
	var sk [32]byte
	DecodeSymmetricKey(params, key, encrypted.EncryptedKey, sk[:])

	var nonce [24]byte
	output := make([]byte, len(encrypted.EncryptedMessage)-secretbox.Overhead)
	return secretbox.Open(output, encrypted.EncryptedMessage, &nonce, &sk)
}
