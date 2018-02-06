package objs

import (
	"errors"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/entity"
)

//go:generate msgp -tests=false
type HIBEKEY []byte
type AESKey []byte
type Ed25519Signature []byte
type Ed25519VK []byte
type OAQUEKey []byte

//We want to encrypt a dot to also include expiry
//easy way: need permission at the time the dot was granted
//          that sucks
//could encrypt multiple keys at different times, allowing dst to decrypt

//The actual partition ID is OQUE [ partition_label, namespace ]

//This is a DOT as it appears on the wire
type ExternalDOT struct {
	//Public information about the DOT
	PlaintextHeader *PlaintextHeader `msg:"header"`
	//Encrypted using AES128(ContentKey)
	EncryptedContent []byte `msg:"content"`
	//Encrypted using AES128(InheritanceKey)
	EncryptedInheritance []byte `msg:"inheritance"`

	//Encrypted using AES128(PartitionLabelKey), contains the OAQUE ID for delegation keyhole
	EncryptedPartitionLabel []byte `msg:"partition"`
	//This is an OAQUE ciphertext requriing DSTVK[partition_label, namespace]
	EncryptedPartitionLabelKey []byte `msg:"plabelk"`
	//This is an Ed25519 ciphertext requiring DstVK
	EncryptedDirectPartLabelKey []byte `msg:"plabelk2"`

	//This, when ulocked with OQAUE(DSTVK, "partition", Partition) contains the AES
	//keys for both the content and the inheritance
	DelegationKeyhole []byte `msg:"delegationKeyhole"`

	//Encrypted using AES128(ECDH(SigningKey, Auditor)) the GCM allows you
	//to check
	ContentAuditorKeyholes [][]byte `msg:"auditorKeyholes"`

	//Ensures whole-representation of DOT is not modified
	Outersig Ed25519Signature `msg:"osig"`
}

//This is the version used within the program
type DOT struct {
	//Public information about the DOT
	PlaintextHeader *PlaintextHeader
	//Encrypted using AES128(ContentKey)
	EncryptedContent []byte
	//Encrypted using AES128(InheritanceKey)
	EncryptedInheritance []byte

	//Encrypted using AES128(PartitionLabelKey), contains the OAQUE ID for delegation keyhole
	EncryptedPartitionLabel []byte
	//This is an OAQUE ciphertext requriing DSTVK[partition_label, namespace]
	EncryptedPartitionLabelKey []byte
	//This is an Ed25519 ciphertext requiring DstVK
	EncryptedDirectPartLabelKey []byte

	//This, when ulocked with OQAUE(DSTVK, "partition", Partition) contains the AES
	//keys for both the content and the inheritance
	DelegationKeyhole []byte

	//Encrypted using AES128(ECDH(SigningKey, Auditor)) the GCM allows you
	//to check
	ContentAuditorKeyholes [][]byte

	//Ensures whole-representation of DOT is not modified
	Outersig Ed25519Signature

	//Decrypted version (not transmitted, populated later)
	Content           *DOTContent
	PartitionLabel    [][]byte
	Inheritance       *InheritanceMap
	Hash              []byte
	OriginalEncoding  []byte
	SRC               *entity.Entity
	DST               *entity.Entity
	AESContentKeyhole []byte
}

func (ed *ExternalDOT) Internal() *DOT {
	panic("ni")
}

func (d *DOT) External() *ExternalDOT {
	panic("ni")
}

var ErrEncrypted = errors.New("DOT is still encrypted")

//TODO clean up this separate package thing...
func (d *DOT) Expired() (bool, error) {
	if d.Content == nil {
		return false, ErrEncrypted
	}
	expiryTime := time.Unix(0, d.Content.Attributes.Expiry)
	return expiryTime.Before(time.Now()), nil
}

func (d *DOT) HasContent() bool {
	return d.Content != nil
}

func (d *DOT) ArrayHash() [32]byte {
	panic("ni")
}

//This information is all encrypted. It is also signed, so this copy here
//should be used in preference to the label
type DOTContent struct {
	//The originator of the DOT, also the key that signs it
	SRC []byte `msg:"src"`
	//The recipient of the DOT (duplicatd in label)
	DST []byte `msg:"dst"`
	//The namespace. Can be nil to mean global
	NS []byte `msg:"ns"`
	//These are the resources the dot
	URI string `msg:"uri"`
	//These are the permissions the dot confers.
	Permissions []string `msg:"grant"`
	//This is used to store properties about the dot itself
	Attributes *AttributeMap `msg:"attr"`
	//Outersig VK. Ephemeral, so cannot be tied to SRCVK
	//TODO: perhaps omit this in the final packing, and repopulate it from the
	//plaintext header before calculating Signature
	SigningVK Ed25519VK `msg:"sigvk"`
	//Signature. This is set to zeroes when the signature is created
	Signature Ed25519Signature `msg:"signature"`
	//DO NOT ADD FIELDS HERE, PUT THEM ABOVE SIGNATURE
}

//Contains information about the DOT
type AttributeMap struct {
	//Nanoseconds since unix epoch
	Expiry  int64  `msg:"expiry"`
	Created int64  `msg:"created"`
	Contact string `msg:"contact"`
	Comment string `msg:"comment"`
	TTL     int8   `msg:"ttl"`
}

type PartitionLabel [][]byte

//Contains extra data that DOT recipients (and delegated recipients) obtain
//but not proof recipients
type InheritanceMap struct {
	//This key allows the inheritor to read the partition labels of dots
	//granted to SRCVK under the same namespace
	PartitionLabelKey *oaque.PrivateKey `msg:"partitionLabelKey"`
	//Used to decrypt dots granted on no namespace
	GlobalLabelKey *oaque.PrivateKey `msg:"globalLabelKey"`
	//This key allows the inheritor to decrypt dots granted to
	//SRCVK with a partition at or below DelegationPartition
	DelegationKey *oaque.PrivateKey `msg:"delegationKey"`
	//This is the partition key being delegated (the ID for DelegationKey).
	//In general this would
	//be the same as the partition that the dot is encrypted under, but
	//it need not be
	DelegationPartition [][]byte `msg:"delegationPartition"`
	//This is for end-to-end encryption, the ID should be obvious from
	//the permissions in the content of the dot
	E2EESlots [][]byte
	E2EE      *oaque.PrivateKey `msg:"e2ee"`
}

//This information is public
type PlaintextHeader struct {
	//Recipient entity (hash)
	DST []byte `msg:"dst"`
	//Revocation object hash
	RevocationHash []byte `msg:"rvk"`
	//Signing VK. This is ephemeral
	SigVK Ed25519VK `msg:"sigvk"`
}
