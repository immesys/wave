package starwave

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/SoftwareDefinedBuildings/starwave/core"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

type MessageType byte

const (
	TypeInvalidMessage MessageType = iota
	TypeHierarchyDescriptor
	TypeDecryptionKey
	TypePermission
	TypeEntityDescriptor
	TypeEntitySecret
	TypeBroadeningDelegation
	TypeBroadeningDelegationWithKey
	TypeEncryptedSymmetricKey
	TypeEncryptedMessage
	TypeFullDelegation
	TypeDelegationBundle
)

func (messageType MessageType) String() string {
	switch messageType {
	case TypeHierarchyDescriptor:
		return "HierarchyDescriptor"
	case TypeDecryptionKey:
		return "DecryptionKey"
	case TypePermission:
		return "Permission"
	case TypeEntityDescriptor:
		return "EntityDescriptor"
	case TypeEntitySecret:
		return "EntitySecret"
	case TypeBroadeningDelegation:
		return "BroadeningDelegation"
	case TypeBroadeningDelegationWithKey:
		return "BroadeningDelegationWithKey"
	case TypeEncryptedSymmetricKey:
		return "EncryptedSymmetricKey"
	case TypeEncryptedMessage:
		return "EncryptedMessage"
	case TypeFullDelegation:
		return "FullDelegation"
	default:
		panic(fmt.Sprintf("Unknown message type %d", messageType))
	}
}

func (messageType MessageType) Byte() byte {
	return byte(messageType)
}

func newMessageBuffer(cap int, messageType MessageType) []byte {
	buf := make([]byte, 0, cap)
	return append(buf, messageType.Byte())
}

func checkMessageType(message []byte, expected MessageType) []byte {
	if message[0] != expected.Byte() {
		panic(fmt.Sprintf("Got %s, but expected %s", MessageType(message[0]).String(), expected.String()))
	}
	return message[1:]
}

/* Utilities for marshalling array/slice lengths. */

const MarshalledLengthLength = 4

func putLength(buf []byte, length int) {
	binary.LittleEndian.PutUint32(buf, uint32(length))
}

func getLength(buf []byte) int {
	return int(binary.LittleEndian.Uint32(buf))
}

func MarshalAppendLength(length int, buf []byte) []byte {
	lenbuf := make([]byte, MarshalledLengthLength)
	putLength(lenbuf, length)
	return append(buf, lenbuf...)
}

func UnmarshalPrefixLength(buf []byte) (int, []byte) {
	length := getLength(buf[:MarshalledLengthLength])
	buf = buf[MarshalledLengthLength:]
	return length, buf
}

/* Utilities for marshalling more complex structures. */

type Marshallable interface {
	Marshal() []byte
	Unmarshal([]byte) bool
}

func MarshalAppendWithLength(m Marshallable, buf []byte) []byte {
	if m == nil || reflect.ValueOf(m).IsNil() {
		return MarshalAppendLength(0, buf)
	}
	marshalled := m.Marshal()
	buf = MarshalAppendLength(len(marshalled), buf)
	buf = append(buf, marshalled...)
	return buf
}

func UnmarshalPrefixWithLength(m Marshallable, buf []byte) []byte {
	length, buf := UnmarshalPrefixLength(buf)
	if length == 0 {
		// Message was nil
		return buf
	}
	success := m.Unmarshal(buf[:length])
	if !success {
		return nil
	}
	return buf[length:]
}

type MarshallableString struct {
	s string
}

func NewMarshallableString(str string) *MarshallableString {
	return &MarshallableString{str}
}

func NewMarshallableBytes(b []byte) *MarshallableString {
	return &MarshallableString{string(b)}
}

func (ms *MarshallableString) Marshal() []byte {
	return []byte(ms.s)
}

func (ms *MarshallableString) Unmarshal(buf []byte) bool {
	ms.s = string(buf)
	return true
}

func (hd *HierarchyDescriptor) Marshal() []byte {
	buf := newMessageBuffer(1024, TypeHierarchyDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(hd.Nickname), buf)
	buf = MarshalAppendWithLength(hd.Params, buf)
	return buf
}

func (hd *HierarchyDescriptor) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeHierarchyDescriptor)

	ms := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&ms, buf)
	if buf == nil {
		return false
	}
	hd.Nickname = ms.s

	hd.Params = new(oaque.Params)
	buf = UnmarshalPrefixWithLength(hd.Params, buf)
	if buf == nil {
		return false
	}

	return true
}

func (p *Permission) Marshal() []byte {
	buf := newMessageBuffer(1024, TypePermission)

	buf = MarshalAppendWithLength(NewMarshallableBytes(core.URIToBytes(p.URI)), buf)
	buf = MarshalAppendWithLength(NewMarshallableBytes(core.TimeToBytes(p.Time)), buf)
	return buf
}

func (p *Permission) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypePermission)

	uri := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&uri, buf)
	if buf == nil {
		return false
	}
	p.URI = core.URIFromBytes([]byte(uri.s))

	time := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&time, buf)
	if buf == nil {
		return false
	}
	p.Time = core.TimeFromBytes([]byte(time.s))

	return true
}

func (dk *DecryptionKey) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeDecryptionKey)

	buf = MarshalAppendWithLength(dk.Hierarchy, buf)
	buf = MarshalAppendWithLength(dk.Key, buf)
	buf = MarshalAppendWithLength(dk.Permissions, buf)

	return buf
}

func (dk *DecryptionKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeDecryptionKey)

	dk.Hierarchy = new(HierarchyDescriptor)
	buf = UnmarshalPrefixWithLength(dk.Hierarchy, buf)
	if buf == nil {
		return false
	}

	dk.Key = new(oaque.PrivateKey)
	buf = UnmarshalPrefixWithLength(dk.Key, buf)
	if buf == nil {
		return false
	}

	dk.Permissions = new(Permission)
	buf = UnmarshalPrefixWithLength(dk.Permissions, buf)
	if buf == nil {
		return false
	}

	return true
}

func (ed *EntityDescriptor) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeEntityDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(ed.Nickname), buf)
	buf = MarshalAppendWithLength(ed.Params, buf)
	return buf
}

func (ed *EntityDescriptor) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEntityDescriptor)

	ms := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&ms, buf)
	if buf == nil {
		return false
	}
	ed.Nickname = ms.s

	ed.Params = new(oaque.Params)
	buf = UnmarshalPrefixWithLength(ed.Params, buf)
	if buf == nil {
		return false
	}

	return true
}

func (es *EntitySecret) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeEntitySecret)

	buf = MarshalAppendWithLength(es.Key, buf)
	buf = MarshalAppendWithLength(es.Descriptor, buf)

	return buf
}

func (es *EntitySecret) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEntitySecret)

	es.Key = new(oaque.MasterKey)
	buf = UnmarshalPrefixWithLength(es.Key, buf)
	if buf == nil {
		return false
	}

	es.Descriptor = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(es.Descriptor, buf)
	if buf == nil {
		return false
	}

	return true
}

func (esk *EncryptedSymmetricKey) Marshal() []byte {
	buf := newMessageBuffer(1024, TypeEncryptedSymmetricKey)

	buf = MarshalAppendWithLength(esk.Ciphertext, buf)
	buf = MarshalAppendWithLength(esk.Permissions, buf)

	return buf
}

func (esk *EncryptedSymmetricKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEncryptedSymmetricKey)

	esk.Ciphertext = new(oaque.Ciphertext)
	buf = UnmarshalPrefixWithLength(esk.Ciphertext, buf)
	if buf == nil {
		return false
	}

	esk.Permissions = new(Permission)
	buf = UnmarshalPrefixWithLength(esk.Permissions, buf)
	if buf == nil {
		return false
	}

	return true
}

func (em *EncryptedMessage) Marshal() []byte {
	buf := newMessageBuffer(1024+MarshalledLengthLength+len(em.Message), TypeEncryptedMessage)

	buf = MarshalAppendWithLength(em.Key, buf)
	buf = MarshalAppendWithLength(NewMarshallableBytes(em.Message), buf)

	return buf
}

func (em *EncryptedMessage) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEncryptedMessage)

	em.Key = new(EncryptedSymmetricKey)
	buf = UnmarshalPrefixWithLength(em.Key, buf)
	if buf == nil {
		return false
	}

	message := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&message, buf)
	if buf == nil {
		return false
	}
	em.Message = []byte(message.s)

	return true
}

func (bd *BroadeningDelegation) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegation)

	buf = MarshalAppendWithLength(bd.Delegation, buf)
	buf = MarshalAppendWithLength(bd.From, buf)
	buf = MarshalAppendWithLength(bd.To, buf)

	return buf
}

func (bd *BroadeningDelegation) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegation)

	bd.Delegation = new(EncryptedMessage)
	buf = UnmarshalPrefixWithLength(bd.Delegation, buf)
	if buf == nil {
		return false
	}

	bd.From = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bd.From, buf)
	if buf == nil {
		return false
	}

	bd.To = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bd.To, buf)
	if buf == nil {
		return false
	}

	return true
}

func (bdk *BroadeningDelegationWithKey) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegationWithKey)

	buf = MarshalAppendWithLength(bdk.Key, buf)
	buf = MarshalAppendWithLength(bdk.To, buf)
	buf = MarshalAppendWithLength(bdk.Hierarchy, buf)

	return buf
}

func (bdk *BroadeningDelegationWithKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegationWithKey)

	bdk.Key = new(EncryptedMessage)
	buf = UnmarshalPrefixWithLength(bdk.Key, buf)
	if buf == nil {
		return false
	}

	bdk.To = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bdk.To, buf)
	if buf == nil {
		return false
	}

	bdk.Hierarchy = new(HierarchyDescriptor)
	buf = UnmarshalPrefixWithLength(bdk.Hierarchy, buf)
	if buf == nil {
		return false
	}

	return true
}

func (fd *FullDelegation) Marshal() []byte {
	buf := newMessageBuffer(2048+(1024*len(fd.Narrow)), TypeFullDelegation)

	buf = MarshalAppendWithLength(fd.Permissions, buf)
	buf = MarshalAppendWithLength(fd.Broad, buf)
	buf = MarshalAppendLength(len(fd.Narrow), buf)
	/* In any normal FullDelegation, the "To" and "Hierarchy" fields in each
	 * BroadeningDelgationWithKey are the same. In fact, the "To" field is
	 * already in fd.Broad.
	 */
	if len(fd.Narrow) != 0 {
		buf = MarshalAppendWithLength(fd.Narrow[0].Hierarchy, buf)
	}
	for _, narrowing := range fd.Narrow {
		buf = MarshalAppendWithLength(narrowing.Key, buf)
	}

	return buf
}

func (fd *FullDelegation) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeFullDelegation)

	fd.Permissions = new(Permission)
	buf = UnmarshalPrefixWithLength(fd.Permissions, buf)
	fd.Broad = new(BroadeningDelegation)
	buf = UnmarshalPrefixWithLength(fd.Broad, buf)
	if fd.Broad.Delegation == nil {
		fd.Broad = nil
	}

	numNarrowing, buf := UnmarshalPrefixLength(buf)
	var hierarchy *HierarchyDescriptor
	if numNarrowing != 0 {
		hierarchy = new(HierarchyDescriptor)
		buf = UnmarshalPrefixWithLength(hierarchy, buf)
	}
	fd.Narrow = make([]*BroadeningDelegationWithKey, numNarrowing)
	for i := range fd.Narrow {
		key := new(EncryptedMessage)
		buf = UnmarshalPrefixWithLength(key, buf)
		if buf == nil {
			return false
		}
		fd.Narrow[i] = new(BroadeningDelegationWithKey)
		fd.Narrow[i].Key = key
		fd.Narrow[i].To = fd.Broad.To
		fd.Narrow[i].Hierarchy = hierarchy
	}

	return true
}

func (db *DelegationBundle) Marshal() []byte {
	buf := newMessageBuffer(4096, TypeDelegationBundle)

	buf = MarshalAppendLength(len(db.Delegations), buf)
	if len(db.Delegations) != 0 {
		// To, From, and Hierarchy are the exact same for all delegations
		var h *HierarchyDescriptor
		var to *EntityDescriptor
		var from *EntityDescriptor
		for _, deleg := range db.Delegations {
			if deleg.Broad != nil {
				if to == nil {
					to = deleg.Broad.To
				}
				if from == nil {
					from = deleg.Broad.From
				}
				if h != nil {
					break
				}
			}
			if len(deleg.Narrow) != 0 {
				if h == nil {
					h = deleg.Narrow[0].Hierarchy
				}
				if to == nil {
					to = deleg.Narrow[0].To
				}
				if to != nil && from != nil {
					break
				}
			}
		}
		buf = MarshalAppendWithLength(to, buf)
		buf = MarshalAppendWithLength(from, buf)
		buf = MarshalAppendWithLength(h, buf)
	}
	for _, delegation := range db.Delegations {
		buf = MarshalAppendWithLength(delegation.Permissions, buf)
		if delegation.Broad != nil {
			buf = MarshalAppendWithLength(delegation.Broad.Delegation, buf)
		} else {
			buf = MarshalAppendWithLength(delegation.Broad, buf)
		}
		buf = MarshalAppendLength(len(delegation.Narrow), buf)
		for _, narrowing := range delegation.Narrow {
			buf = MarshalAppendWithLength(narrowing.Key, buf)
		}
	}

	return buf
}

func (db *DelegationBundle) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeDelegationBundle)

	numDelegations, buf := UnmarshalPrefixLength(buf)
	if buf == nil {
		return false
	}
	to := new(EntityDescriptor)
	from := new(EntityDescriptor)
	h := new(HierarchyDescriptor)
	if numDelegations != 0 {
		buf = UnmarshalPrefixWithLength(to, buf)
		if buf == nil {
			return false
		}
		buf = UnmarshalPrefixWithLength(from, buf)
		if buf == nil {
			return false
		}
		buf = UnmarshalPrefixWithLength(h, buf)
		if buf == nil {
			return false
		}
	}
	db.Delegations = make([]*FullDelegation, numDelegations)
	for i := range db.Delegations {
		db.Delegations[i] = new(FullDelegation)
		db.Delegations[i].Permissions = new(Permission)
		buf = UnmarshalPrefixWithLength(db.Delegations[i].Permissions, buf)
		if buf == nil {
			return false
		}
		db.Delegations[i].Broad = new(BroadeningDelegation)
		db.Delegations[i].Broad.Delegation = new(EncryptedMessage)
		db.Delegations[i].Broad.From = from
		db.Delegations[i].Broad.To = to
		buf = UnmarshalPrefixWithLength(db.Delegations[i].Broad.Delegation, buf)
		if buf == nil {
			return false
		}

		if db.Delegations[i].Broad.Delegation.Key == nil {
			db.Delegations[i].Broad = nil
		}

		var numNarrowing int
		numNarrowing, buf = UnmarshalPrefixLength(buf)
		if buf == nil {
			return false
		}
		db.Delegations[i].Narrow = make([]*BroadeningDelegationWithKey, numNarrowing)
		for j := range db.Delegations[i].Narrow {
			db.Delegations[i].Narrow[j] = new(BroadeningDelegationWithKey)
			db.Delegations[i].Narrow[j].Hierarchy = h
			db.Delegations[i].Narrow[j].To = to
			db.Delegations[i].Narrow[j].Key = new(EncryptedMessage)
			buf = UnmarshalPrefixWithLength(db.Delegations[i].Narrow[j].Key, buf)
			if buf == nil {
				return false
			}
		}
	}

	return true
}
