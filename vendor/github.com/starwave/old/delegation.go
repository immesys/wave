package core

import (
	"crypto/rand"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

type EntitySystem struct {
	Entity    string
	Params    *oaque.Params
	MasterKey oaque.MasterKey
}

// CreateTopLevel generates a private key with the full privilege of the master
// key. It accepts an integer that should provide the randomness with which to
// generate this key from the master key. Generation of all descendants from
// this key is deterministic; therefore, the randomness in choosing to master
// key, and the randomness provided to this function, together script the
// randomness for the entire OAQUE cryptosystem.
// The reason to use this function instead of using the master key directly is
// for orthogonality. The master key has a different type, whereas all private
// keys have the same type.
func CreateTopLevel() StarWaveKey {
	params, masterKey, err := oaque.Setup(rand.Reader, MaxURILength+MaxTimeLength)
	if err != nil {
		panic(err)
	}
	random, err := oaque.RandomInZp(rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := oaque.KeyGen(random, params, masterKey, make(map[oaque.AttributeIndex]*big.Int))
	if err != nil {
		panic(err)
	}
	return StarWaveKey{
		Key:      key,
		UriPath:  URIPath{},
		TimePath: TimePath{},
	}
}

// GenerateChild generates a subkey from a key. The key must have a superset of
// the permissions described by the provided URI and time; otherwise, the
// behavior of this function is undefined.
func GenerateChild(params *oaque.Params, key StarWaveKey, uri URIPath, time TimePath) StarWaveKey {
	attrs := AttributeSetFromPaths(uri, time)
	t, err := oaque.RandomInZp(rand.Reader)
	if err != nil {
		panic(err)
	}
	qualified, err := oaque.QualifyKey(t, params, key.Key, attrs)
	if err != nil {
		panic(err)
	}
	return StarWaveKey{
		Key:      qualified,
		UriPath:  uri,
		TimePath: time,
	}
}

// DelegateKeyToEntity takes the given StarWaveKey and encrypts it under the
// correct key in the recipient's OAQUE system.
func DeletegateKeyToEntity(key StarWaveKey, entity EntitySystem) EncryptedSingleMessage {
	marshalled := key.Marshal()
	encrypted := EncryptSingle(entity.Params, key.UriPath, key.TimePath, marshalled)
	return encrypted
}
