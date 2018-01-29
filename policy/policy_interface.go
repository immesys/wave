package policy

type Policy interface {
	//The namespace achieves two things
	// a) it bounds the search of DOTs when forming a proof, even if the policy
	//    comparison functions are heavyweight
	// b) it defines the entity with absolute authority for policies interacting
	//    with subjects in this domain
	Namespace() []byte
	//This is an "unguessable" id that is used to encrypt the policy
	//e.g the URI + some salt
	PartitionID() [][]byte
	//This is a guessable id that allows the recipient to decrypt the
	//Partition ID
	//e.g the namespace
	PartitionLabelID() [][]byte
	//These are the keys that should be included in the DOT for decrypting
	//the main partition of incoming dots
	//Probably just the PartitionID without the salt
	// array of slots
	DelegatedPartitionKeyID() [][][]byte

	//TODO make general
	URI() string
	Permissions() []string
}
