package objs

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

//go:generate msgp -test=false

type EntityHash []byte

type Entity struct {
	//== Public content
	//The public verifying key
	VK []byte `msg:"vk"`
	//The public OAQUE parameters
	Params *oaque.Params `msg:"params"`
	//The revocation hash (nil when calculating the hash)
	RevocationHash []byte `msg:"rhash"`
	//The expiry date (seconds since the unix epoch utc. negative means no expiry)
	Expiry int64 `msg:"expiry"`

	//== Private, but stored locally content
	//The signing key
	SK []byte `msg:"sk"`
	//The secret OAQUE key
	MasterKey *oaque.MasterKey `msg:"mk"`

	//== Generated content
	//The hash of the msgpack serialized public content
	Hash EntityHash `msg:"-"`
	//Cached
	publicSerialization []byte `msg:"-"`
	//Cached
	privateSerialization []byte `msg:"-"`
}

//Revocation revelation scheme:
//A revocation is an object:
//(sha256("revoke entity") || entity hash) || SIG
// i.e 64 bytes + 64 byte signature
//This is a "canonical revocation" but frankly it doesn't matter what that
//value really is
//The hash of this whole objet is stored in the entity
//the storage layer can consider any object that hashes to this hash
//as a valid revocation
