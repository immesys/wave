package core

import (
	"crypto/rand"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	msgpack "gopkg.in/vmihailenco/msgpack.v2"
)

type MinPathKey struct {
	Entity   string
	Key      *oaque.PrivateKey
	UriPath  URIPath
	TimePath TimePath
}

func (mpk MinPathKey) Marshal() []byte {
	components := []interface{}{mpk.Entity, mpk.Key.Marshal(), mpk.UriPath, mpk.TimePath}
	marshalled, err := msgpack.Marshal(components)
	if err != nil {
		panic(err)
	}
	return marshalled
}

func (mpk MinPathKey) Unmarshal(marshalled []byte) {
	components := []interface{}{nil, nil, nil, nil}
	err := msgpack.Unmarshal(marshalled, components)
	if err != nil {
		panic(err)
	}
	mpk.Entity = components[0].(string)
	var success bool
	mpk.Key, success = new(oaque.PrivateKey).Unmarshal(components[0].([]byte))
	if !success {
		panic("Invalid private key")
	}
	mpk.UriPath = components[1].(URIPath)
	mpk.TimePath = components[2].(TimePath)
}

func CreateMinPathKey(from EntitySystem, uriPath URIPath, timePath TimePath) MinPathKey {
	attrs := AttributeSetFromPaths(uriPath, timePath)
	r, err := oaque.RandomInZp(rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := oaque.KeyGen(r, from.Params, from.MasterKey, attrs)
	if err != nil {
		panic(err)
	}
	return MinPathKey{
		Key:      key,
		UriPath:  uriPath,
		TimePath: timePath,
	}
}

// DelegateMinPathKeyToEntity takes the given MinPathKey and encrypts it under
// correct key in the recipient's OAQUE system.
func DeletegateMinPathKeyToEntity(key MinPathKey, entity EntitySystem) EncryptedSingleMessage {
	marshalled := key.Marshal()
	encrypted := EncryptSingle(entity.Params, key.UriPath, key.TimePath, marshalled)
	return encrypted
}
