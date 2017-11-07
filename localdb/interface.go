package localdb

import (
	"context"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/tinylib/msgp/msgp"
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

type LowLevelStorage interface {
	Load(path string, into msgp.Unmarshaler) (ok bool, err error)
	LoadPrefix(path string, into msgp.Unmarshaler) (results chan msgp.Unmarshaler, err error)
	Store(path string, from msgp.Marshaler) (err error)
}

//
type WaveState interface {
	LoadSecretEd25519Keys() (map[string][]byte, error)
	LoadMasterOAQUEKeys() (map[string]oaque.MasterKey, error)
	LoadNamespaceHints() ([]string, error)
	GetEntityDOTIndex(ctx context.Context, vk []byte) (int, error)
	GetOAQUEParamsForVK(ctx context.Context, vk []byte) ([]byte, error)
	OAQUEKeysFor(ctx context.Context, vk []byte, slots map[int]string, onResult func(k []byte) bool) error
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
