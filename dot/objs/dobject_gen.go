package objs

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *AESKey) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zxvk []byte
		zxvk, err = dc.ReadBytes([]byte((*z)))
		(*z) = AESKey(zxvk)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z AESKey) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z AESKey) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AESKey) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zbzg []byte
		zbzg, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = AESKey(zbzg)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z AESKey) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *AttributeMap) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zbai uint32
	zbai, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zbai > 0 {
		zbai--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "expiry":
			z.Expiry, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "created":
			z.Created, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "contact":
			z.Contact, err = dc.ReadString()
			if err != nil {
				return
			}
		case "comment":
			z.Comment, err = dc.ReadString()
			if err != nil {
				return
			}
		case "ttl":
			z.TTL, err = dc.ReadInt8()
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *AttributeMap) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 5
	// write "expiry"
	err = en.Append(0x85, 0xa6, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.Expiry)
	if err != nil {
		return
	}
	// write "created"
	err = en.Append(0xa7, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.Created)
	if err != nil {
		return
	}
	// write "contact"
	err = en.Append(0xa7, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteString(z.Contact)
	if err != nil {
		return
	}
	// write "comment"
	err = en.Append(0xa7, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteString(z.Comment)
	if err != nil {
		return
	}
	// write "ttl"
	err = en.Append(0xa3, 0x74, 0x74, 0x6c)
	if err != nil {
		return err
	}
	err = en.WriteInt8(z.TTL)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *AttributeMap) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 5
	// string "expiry"
	o = append(o, 0x85, 0xa6, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79)
	o = msgp.AppendInt64(o, z.Expiry)
	// string "created"
	o = append(o, 0xa7, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64)
	o = msgp.AppendInt64(o, z.Created)
	// string "contact"
	o = append(o, 0xa7, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74)
	o = msgp.AppendString(o, z.Contact)
	// string "comment"
	o = append(o, 0xa7, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74)
	o = msgp.AppendString(o, z.Comment)
	// string "ttl"
	o = append(o, 0xa3, 0x74, 0x74, 0x6c)
	o = msgp.AppendInt8(o, z.TTL)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *AttributeMap) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zcmr uint32
	zcmr, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zcmr > 0 {
		zcmr--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "expiry":
			z.Expiry, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "created":
			z.Created, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "contact":
			z.Contact, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "comment":
			z.Comment, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "ttl":
			z.TTL, bts, err = msgp.ReadInt8Bytes(bts)
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *AttributeMap) Msgsize() (s int) {
	s = 1 + 7 + msgp.Int64Size + 8 + msgp.Int64Size + 8 + msgp.StringPrefixSize + len(z.Contact) + 8 + msgp.StringPrefixSize + len(z.Comment) + 4 + msgp.Int8Size
	return
}

// DecodeMsg implements msgp.Decodable
func (z *DOT) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zwht uint32
	zwht, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zwht > 0 {
		zwht--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "header":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.PlaintextHeader = nil
			} else {
				if z.PlaintextHeader == nil {
					z.PlaintextHeader = new(PlaintextHeader)
				}
				err = z.PlaintextHeader.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "content":
			z.EncryptedContent, err = dc.ReadBytes(z.EncryptedContent)
			if err != nil {
				return
			}
		case "inheritance":
			z.EncryptedInheritance, err = dc.ReadBytes(z.EncryptedInheritance)
			if err != nil {
				return
			}
		case "partition":
			z.EncryptedPartitionLabel, err = dc.ReadBytes(z.EncryptedPartitionLabel)
			if err != nil {
				return
			}
		case "plabelk":
			z.EncryptedPartitionLabelKey, err = dc.ReadBytes(z.EncryptedPartitionLabelKey)
			if err != nil {
				return
			}
		case "plabelk2":
			z.EncryptedDirectPartLabelKey, err = dc.ReadBytes(z.EncryptedDirectPartLabelKey)
			if err != nil {
				return
			}
		case "delegationKeyhole":
			z.DelegationKeyhole, err = dc.ReadBytes(z.DelegationKeyhole)
			if err != nil {
				return
			}
		case "auditorKeyholes":
			var zhct uint32
			zhct, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zhct) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zhct]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zhct)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], err = dc.ReadBytes(z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zcua []byte
				zcua, err = dc.ReadBytes([]byte(z.Outersig))
				z.Outersig = Ed25519Signature(zcua)
			}
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *DOT) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 9
	// write "header"
	err = en.Append(0x89, 0xa6, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72)
	if err != nil {
		return err
	}
	if z.PlaintextHeader == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.PlaintextHeader.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "content"
	err = en.Append(0xa7, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedContent)
	if err != nil {
		return
	}
	// write "inheritance"
	err = en.Append(0xab, 0x69, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedInheritance)
	if err != nil {
		return
	}
	// write "partition"
	err = en.Append(0xa9, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedPartitionLabel)
	if err != nil {
		return
	}
	// write "plabelk"
	err = en.Append(0xa7, 0x70, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedPartitionLabelKey)
	if err != nil {
		return
	}
	// write "plabelk2"
	err = en.Append(0xa8, 0x70, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x6b, 0x32)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedDirectPartLabelKey)
	if err != nil {
		return
	}
	// write "delegationKeyhole"
	err = en.Append(0xb1, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.DelegationKeyhole)
	if err != nil {
		return
	}
	// write "auditorKeyholes"
	err = en.Append(0xaf, 0x61, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.ContentAuditorKeyholes)))
	if err != nil {
		return
	}
	for zajw := range z.ContentAuditorKeyholes {
		err = en.WriteBytes(z.ContentAuditorKeyholes[zajw])
		if err != nil {
			return
		}
	}
	// write "osig"
	err = en.Append(0xa4, 0x6f, 0x73, 0x69, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.Outersig))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *DOT) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 9
	// string "header"
	o = append(o, 0x89, 0xa6, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72)
	if z.PlaintextHeader == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.PlaintextHeader.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "content"
	o = append(o, 0xa7, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	o = msgp.AppendBytes(o, z.EncryptedContent)
	// string "inheritance"
	o = append(o, 0xab, 0x69, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	o = msgp.AppendBytes(o, z.EncryptedInheritance)
	// string "partition"
	o = append(o, 0xa9, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e)
	o = msgp.AppendBytes(o, z.EncryptedPartitionLabel)
	// string "plabelk"
	o = append(o, 0xa7, 0x70, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x6b)
	o = msgp.AppendBytes(o, z.EncryptedPartitionLabelKey)
	// string "plabelk2"
	o = append(o, 0xa8, 0x70, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x6b, 0x32)
	o = msgp.AppendBytes(o, z.EncryptedDirectPartLabelKey)
	// string "delegationKeyhole"
	o = append(o, 0xb1, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	o = msgp.AppendBytes(o, z.DelegationKeyhole)
	// string "auditorKeyholes"
	o = append(o, 0xaf, 0x61, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.ContentAuditorKeyholes)))
	for zajw := range z.ContentAuditorKeyholes {
		o = msgp.AppendBytes(o, z.ContentAuditorKeyholes[zajw])
	}
	// string "osig"
	o = append(o, 0xa4, 0x6f, 0x73, 0x69, 0x67)
	o = msgp.AppendBytes(o, []byte(z.Outersig))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *DOT) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zxhx uint32
	zxhx, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zxhx > 0 {
		zxhx--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "header":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.PlaintextHeader = nil
			} else {
				if z.PlaintextHeader == nil {
					z.PlaintextHeader = new(PlaintextHeader)
				}
				bts, err = z.PlaintextHeader.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "content":
			z.EncryptedContent, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedContent)
			if err != nil {
				return
			}
		case "inheritance":
			z.EncryptedInheritance, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedInheritance)
			if err != nil {
				return
			}
		case "partition":
			z.EncryptedPartitionLabel, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedPartitionLabel)
			if err != nil {
				return
			}
		case "plabelk":
			z.EncryptedPartitionLabelKey, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedPartitionLabelKey)
			if err != nil {
				return
			}
		case "plabelk2":
			z.EncryptedDirectPartLabelKey, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedDirectPartLabelKey)
			if err != nil {
				return
			}
		case "delegationKeyhole":
			z.DelegationKeyhole, bts, err = msgp.ReadBytesBytes(bts, z.DelegationKeyhole)
			if err != nil {
				return
			}
		case "auditorKeyholes":
			var zlqf uint32
			zlqf, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zlqf) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zlqf]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zlqf)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], bts, err = msgp.ReadBytesBytes(bts, z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zdaf []byte
				zdaf, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Outersig))
				z.Outersig = Ed25519Signature(zdaf)
			}
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *DOT) Msgsize() (s int) {
	s = 1 + 7
	if z.PlaintextHeader == nil {
		s += msgp.NilSize
	} else {
		s += z.PlaintextHeader.Msgsize()
	}
	s += 8 + msgp.BytesPrefixSize + len(z.EncryptedContent) + 12 + msgp.BytesPrefixSize + len(z.EncryptedInheritance) + 10 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabel) + 8 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabelKey) + 9 + msgp.BytesPrefixSize + len(z.EncryptedDirectPartLabelKey) + 18 + msgp.BytesPrefixSize + len(z.DelegationKeyhole) + 16 + msgp.ArrayHeaderSize
	for zajw := range z.ContentAuditorKeyholes {
		s += msgp.BytesPrefixSize + len(z.ContentAuditorKeyholes[zajw])
	}
	s += 5 + msgp.BytesPrefixSize + len([]byte(z.Outersig))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *DOTContent) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zjfb uint32
	zjfb, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zjfb > 0 {
		zjfb--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "src":
			z.SRC, err = dc.ReadBytes(z.SRC)
			if err != nil {
				return
			}
		case "dst":
			z.DST, err = dc.ReadBytes(z.DST)
			if err != nil {
				return
			}
		case "uri":
			z.URI, err = dc.ReadString()
			if err != nil {
				return
			}
		case "grant":
			var zcxo uint32
			zcxo, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zcxo) {
				z.Permissions = (z.Permissions)[:zcxo]
			} else {
				z.Permissions = make([]string, zcxo)
			}
			for zpks := range z.Permissions {
				z.Permissions[zpks], err = dc.ReadString()
				if err != nil {
					return
				}
			}
		case "attr":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Attributes = nil
			} else {
				if z.Attributes == nil {
					z.Attributes = new(AttributeMap)
				}
				err = z.Attributes.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "sigvk":
			{
				var zeff []byte
				zeff, err = dc.ReadBytes([]byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zeff)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zrsw []byte
				zrsw, err = dc.ReadBytes([]byte(z.Signature))
				z.Signature = Ed25519Signature(zrsw)
			}
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *DOTContent) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 7
	// write "src"
	err = en.Append(0x87, 0xa3, 0x73, 0x72, 0x63)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.SRC)
	if err != nil {
		return
	}
	// write "dst"
	err = en.Append(0xa3, 0x64, 0x73, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.DST)
	if err != nil {
		return
	}
	// write "uri"
	err = en.Append(0xa3, 0x75, 0x72, 0x69)
	if err != nil {
		return err
	}
	err = en.WriteString(z.URI)
	if err != nil {
		return
	}
	// write "grant"
	err = en.Append(0xa5, 0x67, 0x72, 0x61, 0x6e, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Permissions)))
	if err != nil {
		return
	}
	for zpks := range z.Permissions {
		err = en.WriteString(z.Permissions[zpks])
		if err != nil {
			return
		}
	}
	// write "attr"
	err = en.Append(0xa4, 0x61, 0x74, 0x74, 0x72)
	if err != nil {
		return err
	}
	if z.Attributes == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Attributes.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "sigvk"
	err = en.Append(0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.SigningVK))
	if err != nil {
		return
	}
	// write "signature"
	err = en.Append(0xa9, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.Signature))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *DOTContent) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 7
	// string "src"
	o = append(o, 0x87, 0xa3, 0x73, 0x72, 0x63)
	o = msgp.AppendBytes(o, z.SRC)
	// string "dst"
	o = append(o, 0xa3, 0x64, 0x73, 0x74)
	o = msgp.AppendBytes(o, z.DST)
	// string "uri"
	o = append(o, 0xa3, 0x75, 0x72, 0x69)
	o = msgp.AppendString(o, z.URI)
	// string "grant"
	o = append(o, 0xa5, 0x67, 0x72, 0x61, 0x6e, 0x74)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Permissions)))
	for zpks := range z.Permissions {
		o = msgp.AppendString(o, z.Permissions[zpks])
	}
	// string "attr"
	o = append(o, 0xa4, 0x61, 0x74, 0x74, 0x72)
	if z.Attributes == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Attributes.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "sigvk"
	o = append(o, 0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
	o = msgp.AppendBytes(o, []byte(z.SigningVK))
	// string "signature"
	o = append(o, 0xa9, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65)
	o = msgp.AppendBytes(o, []byte(z.Signature))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *DOTContent) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zxpk uint32
	zxpk, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zxpk > 0 {
		zxpk--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "src":
			z.SRC, bts, err = msgp.ReadBytesBytes(bts, z.SRC)
			if err != nil {
				return
			}
		case "dst":
			z.DST, bts, err = msgp.ReadBytesBytes(bts, z.DST)
			if err != nil {
				return
			}
		case "uri":
			z.URI, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "grant":
			var zdnj uint32
			zdnj, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zdnj) {
				z.Permissions = (z.Permissions)[:zdnj]
			} else {
				z.Permissions = make([]string, zdnj)
			}
			for zpks := range z.Permissions {
				z.Permissions[zpks], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "attr":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Attributes = nil
			} else {
				if z.Attributes == nil {
					z.Attributes = new(AttributeMap)
				}
				bts, err = z.Attributes.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "sigvk":
			{
				var zobc []byte
				zobc, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zobc)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zsnv []byte
				zsnv, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Signature))
				z.Signature = Ed25519Signature(zsnv)
			}
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *DOTContent) Msgsize() (s int) {
	s = 1 + 4 + msgp.BytesPrefixSize + len(z.SRC) + 4 + msgp.BytesPrefixSize + len(z.DST) + 4 + msgp.StringPrefixSize + len(z.URI) + 6 + msgp.ArrayHeaderSize
	for zpks := range z.Permissions {
		s += msgp.StringPrefixSize + len(z.Permissions[zpks])
	}
	s += 5
	if z.Attributes == nil {
		s += msgp.NilSize
	} else {
		s += z.Attributes.Msgsize()
	}
	s += 6 + msgp.BytesPrefixSize + len([]byte(z.SigningVK)) + 10 + msgp.BytesPrefixSize + len([]byte(z.Signature))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *Ed25519Signature) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zkgt []byte
		zkgt, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519Signature(zkgt)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z Ed25519Signature) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z Ed25519Signature) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Ed25519Signature) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zema []byte
		zema, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519Signature(zema)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z Ed25519Signature) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *Ed25519VK) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zpez []byte
		zpez, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519VK(zpez)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z Ed25519VK) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z Ed25519VK) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Ed25519VK) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zqke []byte
		zqke, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519VK(zqke)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z Ed25519VK) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *HIBEKEY) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zqyh []byte
		zqyh, err = dc.ReadBytes([]byte((*z)))
		(*z) = HIBEKEY(zqyh)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z HIBEKEY) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z HIBEKEY) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *HIBEKEY) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zyzr []byte
		zyzr, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = HIBEKEY(zyzr)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z HIBEKEY) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *InheritanceMap) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zjpj uint32
	zjpj, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zjpj > 0 {
		zjpj--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "partitionLabelKey":
			{
				var zzpf []byte
				zzpf, err = dc.ReadBytes([]byte(z.PartitionLabelKey))
				z.PartitionLabelKey = OAQUEKey(zzpf)
			}
			if err != nil {
				return
			}
		case "delegationKey":
			{
				var zrfe []byte
				zrfe, err = dc.ReadBytes([]byte(z.DelegationKey))
				z.DelegationKey = OAQUEKey(zrfe)
			}
			if err != nil {
				return
			}
		case "delegationPartition":
			var zgmo uint32
			zgmo, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(zgmo) {
				z.DelegationPartition = (z.DelegationPartition)[:zgmo]
			} else {
				z.DelegationPartition = make([][]byte, zgmo)
			}
			for zywj := range z.DelegationPartition {
				z.DelegationPartition[zywj], err = dc.ReadBytes(z.DelegationPartition[zywj])
				if err != nil {
					return
				}
			}
		case "e2ee":
			{
				var ztaf []byte
				ztaf, err = dc.ReadBytes([]byte(z.E2EE))
				z.E2EE = OAQUEKey(ztaf)
			}
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *InheritanceMap) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 4
	// write "partitionLabelKey"
	err = en.Append(0x84, 0xb1, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.PartitionLabelKey))
	if err != nil {
		return
	}
	// write "delegationKey"
	err = en.Append(0xad, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.DelegationKey))
	if err != nil {
		return
	}
	// write "delegationPartition"
	err = en.Append(0xb3, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.DelegationPartition)))
	if err != nil {
		return
	}
	for zywj := range z.DelegationPartition {
		err = en.WriteBytes(z.DelegationPartition[zywj])
		if err != nil {
			return
		}
	}
	// write "e2ee"
	err = en.Append(0xa4, 0x65, 0x32, 0x65, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.E2EE))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *InheritanceMap) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 4
	// string "partitionLabelKey"
	o = append(o, 0x84, 0xb1, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	o = msgp.AppendBytes(o, []byte(z.PartitionLabelKey))
	// string "delegationKey"
	o = append(o, 0xad, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79)
	o = msgp.AppendBytes(o, []byte(z.DelegationKey))
	// string "delegationPartition"
	o = append(o, 0xb3, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e)
	o = msgp.AppendArrayHeader(o, uint32(len(z.DelegationPartition)))
	for zywj := range z.DelegationPartition {
		o = msgp.AppendBytes(o, z.DelegationPartition[zywj])
	}
	// string "e2ee"
	o = append(o, 0xa4, 0x65, 0x32, 0x65, 0x65)
	o = msgp.AppendBytes(o, []byte(z.E2EE))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *InheritanceMap) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zeth uint32
	zeth, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zeth > 0 {
		zeth--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "partitionLabelKey":
			{
				var zsbz []byte
				zsbz, bts, err = msgp.ReadBytesBytes(bts, []byte(z.PartitionLabelKey))
				z.PartitionLabelKey = OAQUEKey(zsbz)
			}
			if err != nil {
				return
			}
		case "delegationKey":
			{
				var zrjx []byte
				zrjx, bts, err = msgp.ReadBytesBytes(bts, []byte(z.DelegationKey))
				z.DelegationKey = OAQUEKey(zrjx)
			}
			if err != nil {
				return
			}
		case "delegationPartition":
			var zawn uint32
			zawn, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(zawn) {
				z.DelegationPartition = (z.DelegationPartition)[:zawn]
			} else {
				z.DelegationPartition = make([][]byte, zawn)
			}
			for zywj := range z.DelegationPartition {
				z.DelegationPartition[zywj], bts, err = msgp.ReadBytesBytes(bts, z.DelegationPartition[zywj])
				if err != nil {
					return
				}
			}
		case "e2ee":
			{
				var zwel []byte
				zwel, bts, err = msgp.ReadBytesBytes(bts, []byte(z.E2EE))
				z.E2EE = OAQUEKey(zwel)
			}
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *InheritanceMap) Msgsize() (s int) {
	s = 1 + 18 + msgp.BytesPrefixSize + len([]byte(z.PartitionLabelKey)) + 14 + msgp.BytesPrefixSize + len([]byte(z.DelegationKey)) + 20 + msgp.ArrayHeaderSize
	for zywj := range z.DelegationPartition {
		s += msgp.BytesPrefixSize + len(z.DelegationPartition[zywj])
	}
	s += 5 + msgp.BytesPrefixSize + len([]byte(z.E2EE))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *OAQUEKey) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zrbe []byte
		zrbe, err = dc.ReadBytes([]byte((*z)))
		(*z) = OAQUEKey(zrbe)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z OAQUEKey) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z OAQUEKey) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *OAQUEKey) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zmfd []byte
		zmfd, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = OAQUEKey(zmfd)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z OAQUEKey) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *PartitionLabel) DecodeMsg(dc *msgp.Reader) (err error) {
	var zbal uint32
	zbal, err = dc.ReadArrayHeader()
	if err != nil {
		return
	}
	if cap((*z)) >= int(zbal) {
		(*z) = (*z)[:zbal]
	} else {
		(*z) = make(PartitionLabel, zbal)
	}
	for zelx := range *z {
		(*z)[zelx], err = dc.ReadBytes((*z)[zelx])
		if err != nil {
			return
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z PartitionLabel) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteArrayHeader(uint32(len(z)))
	if err != nil {
		return
	}
	for zjqz := range z {
		err = en.WriteBytes(z[zjqz])
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z PartitionLabel) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendArrayHeader(o, uint32(len(z)))
	for zjqz := range z {
		o = msgp.AppendBytes(o, z[zjqz])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PartitionLabel) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var ztmt uint32
	ztmt, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		return
	}
	if cap((*z)) >= int(ztmt) {
		(*z) = (*z)[:ztmt]
	} else {
		(*z) = make(PartitionLabel, ztmt)
	}
	for zkct := range *z {
		(*z)[zkct], bts, err = msgp.ReadBytesBytes(bts, (*z)[zkct])
		if err != nil {
			return
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z PartitionLabel) Msgsize() (s int) {
	s = msgp.ArrayHeaderSize
	for ztco := range z {
		s += msgp.BytesPrefixSize + len(z[ztco])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *PlaintextHeader) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zana uint32
	zana, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zana > 0 {
		zana--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "dst":
			z.DST, err = dc.ReadBytes(z.DST)
			if err != nil {
				return
			}
		case "rvk":
			z.RevocationHash, err = dc.ReadBytes(z.RevocationHash)
			if err != nil {
				return
			}
		case "sigvk":
			{
				var ztyy []byte
				ztyy, err = dc.ReadBytes([]byte(z.SigVK))
				z.SigVK = Ed25519VK(ztyy)
			}
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *PlaintextHeader) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "dst"
	err = en.Append(0x83, 0xa3, 0x64, 0x73, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.DST)
	if err != nil {
		return
	}
	// write "rvk"
	err = en.Append(0xa3, 0x72, 0x76, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.RevocationHash)
	if err != nil {
		return
	}
	// write "sigvk"
	err = en.Append(0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.SigVK))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *PlaintextHeader) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "dst"
	o = append(o, 0x83, 0xa3, 0x64, 0x73, 0x74)
	o = msgp.AppendBytes(o, z.DST)
	// string "rvk"
	o = append(o, 0xa3, 0x72, 0x76, 0x6b)
	o = msgp.AppendBytes(o, z.RevocationHash)
	// string "sigvk"
	o = append(o, 0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
	o = msgp.AppendBytes(o, []byte(z.SigVK))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PlaintextHeader) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zinl uint32
	zinl, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zinl > 0 {
		zinl--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "dst":
			z.DST, bts, err = msgp.ReadBytesBytes(bts, z.DST)
			if err != nil {
				return
			}
		case "rvk":
			z.RevocationHash, bts, err = msgp.ReadBytesBytes(bts, z.RevocationHash)
			if err != nil {
				return
			}
		case "sigvk":
			{
				var zare []byte
				zare, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigVK))
				z.SigVK = Ed25519VK(zare)
			}
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *PlaintextHeader) Msgsize() (s int) {
	s = 1 + 4 + msgp.BytesPrefixSize + len(z.DST) + 4 + msgp.BytesPrefixSize + len(z.RevocationHash) + 6 + msgp.BytesPrefixSize + len([]byte(z.SigVK))
	return
}
