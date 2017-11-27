package entity

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

//go:generate msgp -tests=false

type ExternalEntity struct {
	//== Public content
	//The public verifying key
	VK []byte `msg:"vk"`
	//The public OAQUE parameters
	Params *oaque.Params `msg:"params"`
	//The revocation hash
	RevocationHash []byte `msg:"rhash"`
	//The expiry date (seconds since the unix epoch utc. negative means no expiry)
	Expiry int64 `msg:"expiry"`
}

type Entity struct {
	//== Public content
	//The public verifying key
	VK []byte
	//The public OAQUE parameters
	Params *oaque.Params
	//The revocation hash
	RevocationHash []byte
	//The expiry date (seconds since the unix epoch utc. negative means no expiry)
	Expiry int64

	//== Private, but stored locally content
	//The signing key
	SK []byte
	//The secret OAQUE key
	MasterKey *oaque.MasterKey

	//== Generated content
	//The hash of the msgpack serialized public content
	Hash []byte
	//Cached
	publicSerialization []byte
	//Cached
	privateSerialization []byte
}

// //Used only for serialization
// type InternalEntity struct {
// 	VK             []byte           `msg:"vk"`
// 	Params         *oaque.Params    `msg:"params"`
// 	RevocationHash []byte           `msg:"rhash"`
// 	Expiry         int64            `msg:"expiry"`
// 	SK             []byte           `msg:"sk"`
// 	MasterKey      *oaque.MasterKey `msg:"mk"`
// 	Hash           []byte           `msg:"hash"`
// 	//Cached
// 	publicSerialization []byte `msg:"-"`
// 	//Cached
// 	privateSerialization []byte `msg:"-"`
// }

//Revocation revelation scheme:
//A revocation is an object:
//(sha256("revoke entity") || entity hash) || SIG
// i.e 64 bytes + 64 byte signature
//This is a "canonical revocation" but frankly it doesn't matter what that
//value really is
//The hash of this whole objet is stored in the entity
//the storage layer can consider any object that hashes to this hash
//as a valid revocation
