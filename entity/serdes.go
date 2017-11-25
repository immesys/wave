package entity

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	wavecrypto "github.com/immesys/wave/crypto"
	"github.com/immesys/wave/entity/objs"
	"github.com/immesys/wave/params"
)

type Entity objs.Entity
type EntityHash = objs.EntityHash

//Generate a new random entity
func NewEntity() *Entity {
	rv := Entity{}
	var err error
	rv.Params, rv.MasterKey, err = oaque.Setup(rand.Reader, params.OAQUESlots)
	if err != nil {
		panic(err)
	}
	rv.SK, rv.VK = wavecrypto.GenerateKeypair()

	rvk, err := rv.GenerateRevocationObject()
	if err != nil {
		panic(err)
	}
	revocationHash := sha3.NewKeccak256()
	revocationHash.Write(rvk)
	rv.RevocationHash = revocationHash.Sum(nil)

	serialization, err := rv.SerializePublic()
	entityHash := sha3.NewKeccak256()
	entityHash.Write(serialization)
	rv.Hash = EntityHash(entityHash.Sum(nil))
	return &rv
}

//Only generate some of the entity, faster for specific applications
//It does not have a revocation hash nor an entity hash
func NewPartialEntity(doEd25519 bool, doOaque bool) *Entity {
	rv := Entity{}
	var err error
	if doOaque {
		rv.Params, rv.MasterKey, err = oaque.Setup(rand.Reader, params.OAQUESlots)
		if err != nil {
			panic(err)
		}
	}
	if doEd25519 {
		rv.SK, rv.VK = wavecrypto.GenerateKeypair()
	}
	return &rv
}

var ErrNoSigningKey = errors.New("entity has no signing key")
var ErrSignatureInvalid = errors.New("ed25519 signature is invalid")

//RemoveSecrets will modify this entity and remove all secret
//information (such as private keys)
func (e *Entity) RemoveSecrets() *Entity {
	e.SK = nil
	e.MasterKey = nil
	return e
}

//Check that all the fields in the entity are correct. If the SK
//is present, also verify it matches the VK
func (e *Entity) Validate() error {
	if !wavecrypto.CheckKeypair(e.SK, e.VK) {
		return fmt.Errorf("ed25519 keypair is invalid")
	}
	return nil
}

//Returns an error if the entity does not have the SK
func (e *Entity) Ed25519Sign(msg []byte) ([]byte, error) {
	if e.SK == nil {
		return nil, ErrNoSigningKey
	}
	sig := make([]byte, 64)
	wavecrypto.SignBlob(e.SK, e.VK, sig, msg)
	return sig, nil
}

//Returns nil if the signature is correct
func (e *Entity) Ed25519Verify(msg []byte, sig []byte) error {
	if !wavecrypto.VerifyBlob(e.VK, sig, msg) {
		return ErrSignatureInvalid
	}
	return nil
}

//Generates a shared secret using ECDH on curve25519 with the given
//verifying key / public key
func (e *Entity) Curve25519ECDH(vk []byte, nonce []byte, size int) ([]byte, error) {
	if e.SK == nil {
		return nil, ErrNoSigningKey
	}
	dst := make([]byte, size)
	secret := wavecrypto.Ed25519CalcSecret(e.SK, vk)
	shake := sha3.NewShake256()
	shake.Write(secret)
	shake.Write(nonce)
	shake.Read(dst)
	return dst, nil
}

func (e *Entity) GenerateRevocationObject() ([]byte, error) {
	//A revocation for an entity is a 64 byte object plus a signature
	//the first 32 bytes are sha3("entity revocation"), the second 32
	//are the VK. Clearly an entity must not arbitrarily sign things
	//otherwise it can be fooled into making one of these objects
	if e.SK == nil {
		return nil, ErrNoSigningKey
	}
	obj := make([]byte, 128)
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write([]byte("entity revocation"))
	hsh.Sum(obj[0:32])
	copy(obj[32:64], e.VK)
	sig, err := e.Ed25519Sign(obj[0:64])
	if err != nil {
		//We validated SK above
		panic("unexpected signing error")
	}
	copy(obj[64:128], sig)
	return obj, nil
}

//Serialize this entity with secrets included
func (e *Entity) SerializePrivate() ([]byte, error) {
	x := objs.Entity(*e)
	return x.MarshalMsg(nil)
}

//Serialize the public form of this entity
func (e *Entity) SerializePublic() ([]byte, error) {
	copy := Entity{}
	copy.VK = e.VK
	copy.Params = e.Params
	copy.RevocationHash = nil
	x := objs.Entity(copy)
	return x.MarshalMsg(nil)
}

func (e *Entity) StringHash() string {
	if len(e.Hash) != 32 {
		panic("StringHash() called on entity with no Hash")
	}
	return wavecrypto.FmtHash(e.Hash)
}
