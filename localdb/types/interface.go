package types

import (
	"context"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/dot"
)

//What do we need to store
// entity
//   - field index
//   -
/*
VK/
 - seqno (how far we have processed on this VK)
 - partlabelNamespaces/
  - a list of every namespace we have tried when
    decrypting partition labels. Don't reprocess
    if you receive a dot from this vk on the same
    namespace, it won't get you more dots
 - unprocessed dots/
   - partkey/
   - every dot we could not decrypt destined to this VK
*/

//Questions
//What new dots do I need to process from the chain
// A: the list of interesting dst VKs and the dot index for each
//What new fields do I need to process from the chain
// A: the list of interesting VKs and the field index for each
//What new attestations do I need to process from the chain
// A: the list of interesting VKs and the attestation index for each

//For a given entity, the partition label keys
// A: one per namespace that I have a dot on (and global namespace)
//What partition label keys should I try on existing dots to an entity
// A: for each new namespace unlocked by an entity grant, assign it a number
//    (namespace index from VK_A). For each dot TO an entity, store the index
//    of the latest namespace index tried to unlock it. You only re-examine
//    a DOT if a new namespace is added.
//The list of dot hashes that we have not been able to decrypt at all
//  For each one, the namespace index we have tried
//The list of dot hashes that we know the partition of
// VK->PartitionLabel->Hash

//For a given entity, the list of dots granted to it (/VK/INDEX -> hash)
// For each one: the namespace index that we have tried
// The partition label (if known)
// The content

//DOT hash -> DOT content
//List of interested entities
//List of interested namespaces
//Work queue

type KeyValue struct {
	Key   string
	Value []byte
}
type LowLevelStorage interface {
	//If the key does not exist, return nil value and nil err
	Load(ctx context.Context, key string) (val []byte, err error)
	//For both of these functions, you either have to fully consume the value channel,
	//or cancel the context.
	LoadPrefix(ctx context.Context, key string) (results chan KeyValue, err chan error)
	//Values will be nil
	LoadPrefixKeys(ctx context.Context, key string) (results chan KeyValue, err chan error)
	Store(ctx context.Context, key string, val []byte) (err error)
}

type PendingDOTResult struct {
	Err        error
	Ciphertext []byte
	Hash       []byte
	//Only for pending without partition
	SecretIndex *int
}

type Secret struct {
	//If true, this is a main content key,
	//If false this is a label key
	IsPartitionKey bool
	Slots          [][]byte
	Key            *oaque.PrivateKey
}

type InterestingEntityResult struct {
	VK  []byte
	Err error
}

//Retrieving dots:
//for pending with partition:
// we need to be able to retrieve only the dots that we expect to be able to decrypt
// lookup(dstvk, slots)
//for pending
// naive: try every partition label key when we get it
// later: filter by interesting namespzaces

//A wave state is the state associate WITH A SINGLE ENTITY.
//So everything accessed in the underying db needs to be super careful
//to not accidentally let one entity see what another is doing on the agent
type WaveState interface {

	//An entity that should be inspected
	//Pipeline is IGNORED->INTERESTING
	InsertInterestingEntity(ctx context.Context, hash []byte) error
	GetInterestingEntities(ctx context.Context) chan InterestingEntityResult

	//Fully decoded DOT
	InsertDOT(ctx context.Context, dt *dot.DOT) error

	//Not decoded, but we know the ID of the decryption key
	InsertPendingDOTWithPartition(ctx context.Context, ciphertext []byte, dothash []byte, dst []byte, partition [][]byte) error
	RemovePendingDOTWithPartition(ctx context.Context, dothash []byte, dst []byte) error

	//Returns all the dots that match the given partition
	GetPendingDOTsWithPartition(ctx context.Context, dst []byte, partition [][]byte) chan PendingDOTResult

	//Get the max number of partition label
	GetPartitionLabelSecretIndex(ctx context.Context, dst []byte) (int, error)

	//Not decoded, but we think we would want to try decode it in future
	// The secret index is the index of the last secret we used to try decode the dot's partition
	InsertPendingDOT(ctx context.Context, ciphertext []byte, dothash []byte, dst []byte, secretindex int) error
	UpdatePendingDOTSecretIndex(ctx context.Context, dothash []byte, dst []byte, secretindex int) error
	RemovePendingDOT(ctx context.Context, dothash []byte, dst []byte) error

	//If you return a result with err != nil it must be the last in the channel
	//If the context is cancelled you must close the channel (and not deadlock)
	GetPendingDOTs(ctx context.Context, dst []byte) chan PendingDOTResult

	//This will also call InsertOAQUEKeysFor but will add it to the secret log for the VK
	InsertPartitionLabelSecret(ctx context.Context, dst []byte, ciphertext []byte, partition [][]byte) error
	GetPartitionLabelSecret(ctx context.Context, dst []byte, index int) (*Secret, error)

	GetEntityDOTIndex(ctx context.Context, dst []byte) (int, error)
	SetEntityDOTIndex(ctx context.Context, dst []byte, index int) error
	GetOAQUEParamsForEntity(ctx context.Context, dst []byte) ([]byte, error)
	OAQUEKeysFor(ctx context.Context, dst []byte, slots [][]byte, onResult func(k []byte) bool) error
	InsertOAQUEKeysFor(ctx context.Context, dst []byte, slots [][]byte, key []byte) error
}

//
// type waveState struct {
// 	lls LowLevelStorage
// }
//
// func keyInterestingEntity(vk []byte) string {
// 	return fmt.Sprintf("IE/%X", vk)
// }
// func keyInterestingNamespace(vk []byte) string {
// 	return fmt.Sprintf("IN/%X", vk)
// }
//
// func NewWaveState(lls LowLevelStorage) (WaveState, error) {
// 	return &waveState{lls: lls}, nil
// }
// func (ws *waveState) AddInterestingEntity(vk []byte) error {
// 	return ws.lls.Store(keyInterestingEntity(vk), &objs.Dummy{})
// }
// func (ws *waveState) AddInterestingNamespace(vk []byte) error {
// 	return ws.lls.Store(keyInterestingNamespace(vk), &objs.Dummy{})
// }
