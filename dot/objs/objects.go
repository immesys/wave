package objs

//go:generate msgp
type HIBEKEY []byte
type AESKey []byte
type Ed25519Signature []byte
type Ed25519VK []byte
type OAQUEKey []byte

//This is a DOT as it appears on the wire
type DOT struct {
	//Public information about the DOT
	PlaintextHeader *PlaintextHeader `msg:"header"`
	//Encrypted using AES128(ContentKey_AES128)
	EncryptedContent []byte `msg:"content"`

	//Encrypted using HIBE(dstvk, $/<namespace>)
	EncryptedPartitionLabel []byte `msg:"plabel"`
	//This key requires knowing the namespace:
	EncryptedPartitionLabelKey []byte `msg:"plabelk"`
	//This key requires being the DST (not delegated)
	EncryptedDirectPartLabelKey []byte `msg:"plabelk2"`
	//TODO when marshalling partition key for delegation, remove the element called B

	//Encrypted using AES128(InheritanceKey)
	EncryptedInheritance []byte `msg:"inheritance"`

	//This, when ulocked with HIBE(DSTVK, Partition) contains the AES
	//keys for both the content and the inheritance
	DelegationKeyhole []byte `msg:"delegationKeyhole"`

	//Encrypted using AES128(ECDH(SigningKey, Auditor)) the GCM allows you
	//to check
	ContentAuditorKeyholes [][]byte `msg:"auditorKeyholes"`

	//Ensures whole-representation of DOT is not modified
	Outersig Ed25519Signature `msg:"osig"`

	//Decrypted version (not transmitted, populated later)
	Content        *DOTContent     `msg:"-"`
	PartitionLabel string          `msg:"-"`
	Inheritance    *InheritanceMap `msg:"-"`
}

//This information is all encrypted. It is also signed, so this copy here
//should be used in preference to the label
type DOTContent struct {
	//The originator of the DOT, also the key that signs it
	SRCVK Ed25519VK `msg:"src"`
	//The recipient of the DOT (duplicatd in label)
	DSTVK Ed25519VK `msg:"dst"`
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
	Expiry  int64  `msg:"expiry"`
	Created int64  `msg:"created"`
	Contact string `msg:"contact"`
	Comment string `msg:"comment"`
	TTL     int8   `msg:"ttl"`
}

//Contains extra data that DOT recipients (and delegated recipients) obtain
//but not proof recipients
type InheritanceMap struct {
	//This key allows the inheritor to read the partitions of dots
	//granted to SRCVK under the same namespace
	PartitionKey HIBEKEY `msg:"partitionKey"`
	//This key allows the inheritor to decrypt dots granted to
	//SRCVK with a partition at or below DelegationPartition
	DelegationKey HIBEKEY `msg:"delegationKey"`
	//This is the partition key being delegated. In general this would
	//be the same as the partition that the dot is encrypted under, but
	//it need not be
	DelegationPartition string `msg:"delegationPartition"`
	//This is for end-to-end encryption
	E2EE OAQUEKey `msg:"e2ee"`
}

//This information is public
type PlaintextHeader struct {
	//Recipient
	DSTVK []byte `msg:"dst"`
	//Signing VK. This is ephemeral
	SigVK []byte `msg:"sigvk"`
}
