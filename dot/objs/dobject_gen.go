package objs

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/entity"
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
	var zhct uint32
	zhct, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zhct > 0 {
		zhct--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "PlaintextHeader":
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
		case "EncryptedContent":
			z.EncryptedContent, err = dc.ReadBytes(z.EncryptedContent)
			if err != nil {
				return
			}
		case "EncryptedInheritance":
			z.EncryptedInheritance, err = dc.ReadBytes(z.EncryptedInheritance)
			if err != nil {
				return
			}
		case "EncryptedPartitionLabel":
			z.EncryptedPartitionLabel, err = dc.ReadBytes(z.EncryptedPartitionLabel)
			if err != nil {
				return
			}
		case "EncryptedPartitionLabelKey":
			z.EncryptedPartitionLabelKey, err = dc.ReadBytes(z.EncryptedPartitionLabelKey)
			if err != nil {
				return
			}
		case "EncryptedDirectPartLabelKey":
			z.EncryptedDirectPartLabelKey, err = dc.ReadBytes(z.EncryptedDirectPartLabelKey)
			if err != nil {
				return
			}
		case "DelegationKeyhole":
			z.DelegationKeyhole, err = dc.ReadBytes(z.DelegationKeyhole)
			if err != nil {
				return
			}
		case "ContentAuditorKeyholes":
			var zcua uint32
			zcua, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zcua) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zcua]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zcua)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], err = dc.ReadBytes(z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "Outersig":
			{
				var zxhx []byte
				zxhx, err = dc.ReadBytes([]byte(z.Outersig))
				z.Outersig = Ed25519Signature(zxhx)
			}
			if err != nil {
				return
			}
		case "Content":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Content = nil
			} else {
				if z.Content == nil {
					z.Content = new(DOTContent)
				}
				err = z.Content.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "PartitionLabel":
			var zlqf uint32
			zlqf, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.PartitionLabel) >= int(zlqf) {
				z.PartitionLabel = (z.PartitionLabel)[:zlqf]
			} else {
				z.PartitionLabel = make([][]byte, zlqf)
			}
			for zwht := range z.PartitionLabel {
				z.PartitionLabel[zwht], err = dc.ReadBytes(z.PartitionLabel[zwht])
				if err != nil {
					return
				}
			}
		case "Inheritance":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Inheritance = nil
			} else {
				if z.Inheritance == nil {
					z.Inheritance = new(InheritanceMap)
				}
				err = z.Inheritance.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "Hash":
			z.Hash, err = dc.ReadBytes(z.Hash)
			if err != nil {
				return
			}
		case "OriginalEncoding":
			z.OriginalEncoding, err = dc.ReadBytes(z.OriginalEncoding)
			if err != nil {
				return
			}
		case "SRC":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.SRC = nil
			} else {
				if z.SRC == nil {
					z.SRC = new(entity.Entity)
				}
				err = z.SRC.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "DST":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.DST = nil
			} else {
				if z.DST == nil {
					z.DST = new(entity.Entity)
				}
				err = z.DST.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "AESContentKeyhole":
			z.AESContentKeyhole, err = dc.ReadBytes(z.AESContentKeyhole)
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
	// map header, size 17
	// write "PlaintextHeader"
	err = en.Append(0xde, 0x0, 0x11, 0xaf, 0x50, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72)
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
	// write "EncryptedContent"
	err = en.Append(0xb0, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedContent)
	if err != nil {
		return
	}
	// write "EncryptedInheritance"
	err = en.Append(0xb4, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x49, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedInheritance)
	if err != nil {
		return
	}
	// write "EncryptedPartitionLabel"
	err = en.Append(0xb7, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedPartitionLabel)
	if err != nil {
		return
	}
	// write "EncryptedPartitionLabelKey"
	err = en.Append(0xba, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedPartitionLabelKey)
	if err != nil {
		return
	}
	// write "EncryptedDirectPartLabelKey"
	err = en.Append(0xbb, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x50, 0x61, 0x72, 0x74, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.EncryptedDirectPartLabelKey)
	if err != nil {
		return
	}
	// write "DelegationKeyhole"
	err = en.Append(0xb1, 0x44, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.DelegationKeyhole)
	if err != nil {
		return
	}
	// write "ContentAuditorKeyholes"
	err = en.Append(0xb6, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65, 0x73)
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
	// write "Outersig"
	err = en.Append(0xa8, 0x4f, 0x75, 0x74, 0x65, 0x72, 0x73, 0x69, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteBytes([]byte(z.Outersig))
	if err != nil {
		return
	}
	// write "Content"
	err = en.Append(0xa7, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	if err != nil {
		return err
	}
	if z.Content == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Content.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "PartitionLabel"
	err = en.Append(0xae, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.PartitionLabel)))
	if err != nil {
		return
	}
	for zwht := range z.PartitionLabel {
		err = en.WriteBytes(z.PartitionLabel[zwht])
		if err != nil {
			return
		}
	}
	// write "Inheritance"
	err = en.Append(0xab, 0x49, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	if err != nil {
		return err
	}
	if z.Inheritance == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Inheritance.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "Hash"
	err = en.Append(0xa4, 0x48, 0x61, 0x73, 0x68)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.Hash)
	if err != nil {
		return
	}
	// write "OriginalEncoding"
	err = en.Append(0xb0, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.OriginalEncoding)
	if err != nil {
		return
	}
	// write "SRC"
	err = en.Append(0xa3, 0x53, 0x52, 0x43)
	if err != nil {
		return err
	}
	if z.SRC == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.SRC.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "DST"
	err = en.Append(0xa3, 0x44, 0x53, 0x54)
	if err != nil {
		return err
	}
	if z.DST == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.DST.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "AESContentKeyhole"
	err = en.Append(0xb1, 0x41, 0x45, 0x53, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.AESContentKeyhole)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *DOT) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 17
	// string "PlaintextHeader"
	o = append(o, 0xde, 0x0, 0x11, 0xaf, 0x50, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72)
	if z.PlaintextHeader == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.PlaintextHeader.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "EncryptedContent"
	o = append(o, 0xb0, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	o = msgp.AppendBytes(o, z.EncryptedContent)
	// string "EncryptedInheritance"
	o = append(o, 0xb4, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x49, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	o = msgp.AppendBytes(o, z.EncryptedInheritance)
	// string "EncryptedPartitionLabel"
	o = append(o, 0xb7, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c)
	o = msgp.AppendBytes(o, z.EncryptedPartitionLabel)
	// string "EncryptedPartitionLabelKey"
	o = append(o, 0xba, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	o = msgp.AppendBytes(o, z.EncryptedPartitionLabelKey)
	// string "EncryptedDirectPartLabelKey"
	o = append(o, 0xbb, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x50, 0x61, 0x72, 0x74, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	o = msgp.AppendBytes(o, z.EncryptedDirectPartLabelKey)
	// string "DelegationKeyhole"
	o = append(o, 0xb1, 0x44, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	o = msgp.AppendBytes(o, z.DelegationKeyhole)
	// string "ContentAuditorKeyholes"
	o = append(o, 0xb6, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.ContentAuditorKeyholes)))
	for zajw := range z.ContentAuditorKeyholes {
		o = msgp.AppendBytes(o, z.ContentAuditorKeyholes[zajw])
	}
	// string "Outersig"
	o = append(o, 0xa8, 0x4f, 0x75, 0x74, 0x65, 0x72, 0x73, 0x69, 0x67)
	o = msgp.AppendBytes(o, []byte(z.Outersig))
	// string "Content"
	o = append(o, 0xa7, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74)
	if z.Content == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Content.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "PartitionLabel"
	o = append(o, 0xae, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c)
	o = msgp.AppendArrayHeader(o, uint32(len(z.PartitionLabel)))
	for zwht := range z.PartitionLabel {
		o = msgp.AppendBytes(o, z.PartitionLabel[zwht])
	}
	// string "Inheritance"
	o = append(o, 0xab, 0x49, 0x6e, 0x68, 0x65, 0x72, 0x69, 0x74, 0x61, 0x6e, 0x63, 0x65)
	if z.Inheritance == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Inheritance.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "Hash"
	o = append(o, 0xa4, 0x48, 0x61, 0x73, 0x68)
	o = msgp.AppendBytes(o, z.Hash)
	// string "OriginalEncoding"
	o = append(o, 0xb0, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67)
	o = msgp.AppendBytes(o, z.OriginalEncoding)
	// string "SRC"
	o = append(o, 0xa3, 0x53, 0x52, 0x43)
	if z.SRC == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.SRC.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "DST"
	o = append(o, 0xa3, 0x44, 0x53, 0x54)
	if z.DST == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.DST.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "AESContentKeyhole"
	o = append(o, 0xb1, 0x41, 0x45, 0x53, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x4b, 0x65, 0x79, 0x68, 0x6f, 0x6c, 0x65)
	o = msgp.AppendBytes(o, z.AESContentKeyhole)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *DOT) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zdaf uint32
	zdaf, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zdaf > 0 {
		zdaf--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "PlaintextHeader":
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
		case "EncryptedContent":
			z.EncryptedContent, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedContent)
			if err != nil {
				return
			}
		case "EncryptedInheritance":
			z.EncryptedInheritance, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedInheritance)
			if err != nil {
				return
			}
		case "EncryptedPartitionLabel":
			z.EncryptedPartitionLabel, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedPartitionLabel)
			if err != nil {
				return
			}
		case "EncryptedPartitionLabelKey":
			z.EncryptedPartitionLabelKey, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedPartitionLabelKey)
			if err != nil {
				return
			}
		case "EncryptedDirectPartLabelKey":
			z.EncryptedDirectPartLabelKey, bts, err = msgp.ReadBytesBytes(bts, z.EncryptedDirectPartLabelKey)
			if err != nil {
				return
			}
		case "DelegationKeyhole":
			z.DelegationKeyhole, bts, err = msgp.ReadBytesBytes(bts, z.DelegationKeyhole)
			if err != nil {
				return
			}
		case "ContentAuditorKeyholes":
			var zpks uint32
			zpks, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zpks) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zpks]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zpks)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], bts, err = msgp.ReadBytesBytes(bts, z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "Outersig":
			{
				var zjfb []byte
				zjfb, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Outersig))
				z.Outersig = Ed25519Signature(zjfb)
			}
			if err != nil {
				return
			}
		case "Content":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Content = nil
			} else {
				if z.Content == nil {
					z.Content = new(DOTContent)
				}
				bts, err = z.Content.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "PartitionLabel":
			var zcxo uint32
			zcxo, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.PartitionLabel) >= int(zcxo) {
				z.PartitionLabel = (z.PartitionLabel)[:zcxo]
			} else {
				z.PartitionLabel = make([][]byte, zcxo)
			}
			for zwht := range z.PartitionLabel {
				z.PartitionLabel[zwht], bts, err = msgp.ReadBytesBytes(bts, z.PartitionLabel[zwht])
				if err != nil {
					return
				}
			}
		case "Inheritance":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Inheritance = nil
			} else {
				if z.Inheritance == nil {
					z.Inheritance = new(InheritanceMap)
				}
				bts, err = z.Inheritance.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "Hash":
			z.Hash, bts, err = msgp.ReadBytesBytes(bts, z.Hash)
			if err != nil {
				return
			}
		case "OriginalEncoding":
			z.OriginalEncoding, bts, err = msgp.ReadBytesBytes(bts, z.OriginalEncoding)
			if err != nil {
				return
			}
		case "SRC":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.SRC = nil
			} else {
				if z.SRC == nil {
					z.SRC = new(entity.Entity)
				}
				bts, err = z.SRC.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "DST":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.DST = nil
			} else {
				if z.DST == nil {
					z.DST = new(entity.Entity)
				}
				bts, err = z.DST.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "AESContentKeyhole":
			z.AESContentKeyhole, bts, err = msgp.ReadBytesBytes(bts, z.AESContentKeyhole)
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
	s = 3 + 16
	if z.PlaintextHeader == nil {
		s += msgp.NilSize
	} else {
		s += z.PlaintextHeader.Msgsize()
	}
	s += 17 + msgp.BytesPrefixSize + len(z.EncryptedContent) + 21 + msgp.BytesPrefixSize + len(z.EncryptedInheritance) + 24 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabel) + 27 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabelKey) + 28 + msgp.BytesPrefixSize + len(z.EncryptedDirectPartLabelKey) + 18 + msgp.BytesPrefixSize + len(z.DelegationKeyhole) + 23 + msgp.ArrayHeaderSize
	for zajw := range z.ContentAuditorKeyholes {
		s += msgp.BytesPrefixSize + len(z.ContentAuditorKeyholes[zajw])
	}
	s += 9 + msgp.BytesPrefixSize + len([]byte(z.Outersig)) + 8
	if z.Content == nil {
		s += msgp.NilSize
	} else {
		s += z.Content.Msgsize()
	}
	s += 15 + msgp.ArrayHeaderSize
	for zwht := range z.PartitionLabel {
		s += msgp.BytesPrefixSize + len(z.PartitionLabel[zwht])
	}
	s += 12
	if z.Inheritance == nil {
		s += msgp.NilSize
	} else {
		s += z.Inheritance.Msgsize()
	}
	s += 5 + msgp.BytesPrefixSize + len(z.Hash) + 17 + msgp.BytesPrefixSize + len(z.OriginalEncoding) + 4
	if z.SRC == nil {
		s += msgp.NilSize
	} else {
		s += z.SRC.Msgsize()
	}
	s += 4
	if z.DST == nil {
		s += msgp.NilSize
	} else {
		s += z.DST.Msgsize()
	}
	s += 18 + msgp.BytesPrefixSize + len(z.AESContentKeyhole)
	return
}

// DecodeMsg implements msgp.Decodable
func (z *DOTContent) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zrsw uint32
	zrsw, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zrsw > 0 {
		zrsw--
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
		case "ns":
			z.NS, err = dc.ReadBytes(z.NS)
			if err != nil {
				return
			}
		case "uri":
			z.URI, err = dc.ReadString()
			if err != nil {
				return
			}
		case "grant":
			var zxpk uint32
			zxpk, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zxpk) {
				z.Permissions = (z.Permissions)[:zxpk]
			} else {
				z.Permissions = make([]string, zxpk)
			}
			for zeff := range z.Permissions {
				z.Permissions[zeff], err = dc.ReadString()
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
				var zdnj []byte
				zdnj, err = dc.ReadBytes([]byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zdnj)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zobc []byte
				zobc, err = dc.ReadBytes([]byte(z.Signature))
				z.Signature = Ed25519Signature(zobc)
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
	// map header, size 8
	// write "src"
	err = en.Append(0x88, 0xa3, 0x73, 0x72, 0x63)
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
	// write "ns"
	err = en.Append(0xa2, 0x6e, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.NS)
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
	for zeff := range z.Permissions {
		err = en.WriteString(z.Permissions[zeff])
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
	// map header, size 8
	// string "src"
	o = append(o, 0x88, 0xa3, 0x73, 0x72, 0x63)
	o = msgp.AppendBytes(o, z.SRC)
	// string "dst"
	o = append(o, 0xa3, 0x64, 0x73, 0x74)
	o = msgp.AppendBytes(o, z.DST)
	// string "ns"
	o = append(o, 0xa2, 0x6e, 0x73)
	o = msgp.AppendBytes(o, z.NS)
	// string "uri"
	o = append(o, 0xa3, 0x75, 0x72, 0x69)
	o = msgp.AppendString(o, z.URI)
	// string "grant"
	o = append(o, 0xa5, 0x67, 0x72, 0x61, 0x6e, 0x74)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Permissions)))
	for zeff := range z.Permissions {
		o = msgp.AppendString(o, z.Permissions[zeff])
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
	var zsnv uint32
	zsnv, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zsnv > 0 {
		zsnv--
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
		case "ns":
			z.NS, bts, err = msgp.ReadBytesBytes(bts, z.NS)
			if err != nil {
				return
			}
		case "uri":
			z.URI, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "grant":
			var zkgt uint32
			zkgt, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zkgt) {
				z.Permissions = (z.Permissions)[:zkgt]
			} else {
				z.Permissions = make([]string, zkgt)
			}
			for zeff := range z.Permissions {
				z.Permissions[zeff], bts, err = msgp.ReadStringBytes(bts)
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
				var zema []byte
				zema, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zema)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zpez []byte
				zpez, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Signature))
				z.Signature = Ed25519Signature(zpez)
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
	s = 1 + 4 + msgp.BytesPrefixSize + len(z.SRC) + 4 + msgp.BytesPrefixSize + len(z.DST) + 3 + msgp.BytesPrefixSize + len(z.NS) + 4 + msgp.StringPrefixSize + len(z.URI) + 6 + msgp.ArrayHeaderSize
	for zeff := range z.Permissions {
		s += msgp.StringPrefixSize + len(z.Permissions[zeff])
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
		var zqke []byte
		zqke, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519Signature(zqke)
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
		var zqyh []byte
		zqyh, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519Signature(zqyh)
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
		var zyzr []byte
		zyzr, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519VK(zyzr)
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
		var zywj []byte
		zywj, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519VK(zywj)
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
func (z *ExternalDOT) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zzpf uint32
	zzpf, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zzpf > 0 {
		zzpf--
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
			var zrfe uint32
			zrfe, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zrfe) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zrfe]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zrfe)
			}
			for zjpj := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zjpj], err = dc.ReadBytes(z.ContentAuditorKeyholes[zjpj])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zgmo []byte
				zgmo, err = dc.ReadBytes([]byte(z.Outersig))
				z.Outersig = Ed25519Signature(zgmo)
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
func (z *ExternalDOT) EncodeMsg(en *msgp.Writer) (err error) {
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
	for zjpj := range z.ContentAuditorKeyholes {
		err = en.WriteBytes(z.ContentAuditorKeyholes[zjpj])
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
func (z *ExternalDOT) MarshalMsg(b []byte) (o []byte, err error) {
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
	for zjpj := range z.ContentAuditorKeyholes {
		o = msgp.AppendBytes(o, z.ContentAuditorKeyholes[zjpj])
	}
	// string "osig"
	o = append(o, 0xa4, 0x6f, 0x73, 0x69, 0x67)
	o = msgp.AppendBytes(o, []byte(z.Outersig))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *ExternalDOT) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var ztaf uint32
	ztaf, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for ztaf > 0 {
		ztaf--
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
			var zeth uint32
			zeth, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zeth) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zeth]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zeth)
			}
			for zjpj := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zjpj], bts, err = msgp.ReadBytesBytes(bts, z.ContentAuditorKeyholes[zjpj])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zsbz []byte
				zsbz, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Outersig))
				z.Outersig = Ed25519Signature(zsbz)
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
func (z *ExternalDOT) Msgsize() (s int) {
	s = 1 + 7
	if z.PlaintextHeader == nil {
		s += msgp.NilSize
	} else {
		s += z.PlaintextHeader.Msgsize()
	}
	s += 8 + msgp.BytesPrefixSize + len(z.EncryptedContent) + 12 + msgp.BytesPrefixSize + len(z.EncryptedInheritance) + 10 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabel) + 8 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabelKey) + 9 + msgp.BytesPrefixSize + len(z.EncryptedDirectPartLabelKey) + 18 + msgp.BytesPrefixSize + len(z.DelegationKeyhole) + 16 + msgp.ArrayHeaderSize
	for zjpj := range z.ContentAuditorKeyholes {
		s += msgp.BytesPrefixSize + len(z.ContentAuditorKeyholes[zjpj])
	}
	s += 5 + msgp.BytesPrefixSize + len([]byte(z.Outersig))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *HIBEKEY) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zrjx []byte
		zrjx, err = dc.ReadBytes([]byte((*z)))
		(*z) = HIBEKEY(zrjx)
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
		var zawn []byte
		zawn, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = HIBEKEY(zawn)
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
	var zmfd uint32
	zmfd, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zmfd > 0 {
		zmfd--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "partitionLabelKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.PartitionLabelKey = nil
			} else {
				if z.PartitionLabelKey == nil {
					z.PartitionLabelKey = new(oaque.PrivateKey)
				}
				err = z.PartitionLabelKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "globalLabelKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.GlobalLabelKey = nil
			} else {
				if z.GlobalLabelKey == nil {
					z.GlobalLabelKey = new(oaque.PrivateKey)
				}
				err = z.GlobalLabelKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "delegationKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.DelegationKey = nil
			} else {
				if z.DelegationKey == nil {
					z.DelegationKey = new(oaque.PrivateKey)
				}
				err = z.DelegationKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "delegationPartition":
			var zzdc uint32
			zzdc, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(zzdc) {
				z.DelegationPartition = (z.DelegationPartition)[:zzdc]
			} else {
				z.DelegationPartition = make([][]byte, zzdc)
			}
			for zwel := range z.DelegationPartition {
				z.DelegationPartition[zwel], err = dc.ReadBytes(z.DelegationPartition[zwel])
				if err != nil {
					return
				}
			}
		case "E2EESlots":
			var zelx uint32
			zelx, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.E2EESlots) >= int(zelx) {
				z.E2EESlots = (z.E2EESlots)[:zelx]
			} else {
				z.E2EESlots = make([][]byte, zelx)
			}
			for zrbe := range z.E2EESlots {
				z.E2EESlots[zrbe], err = dc.ReadBytes(z.E2EESlots[zrbe])
				if err != nil {
					return
				}
			}
		case "e2ee":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.E2EE = nil
			} else {
				if z.E2EE == nil {
					z.E2EE = new(oaque.PrivateKey)
				}
				err = z.E2EE.DecodeMsg(dc)
				if err != nil {
					return
				}
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
	// map header, size 6
	// write "partitionLabelKey"
	err = en.Append(0x86, 0xb1, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.PartitionLabelKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.PartitionLabelKey.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "globalLabelKey"
	err = en.Append(0xae, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.GlobalLabelKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.GlobalLabelKey.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "delegationKey"
	err = en.Append(0xad, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.DelegationKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.DelegationKey.EncodeMsg(en)
		if err != nil {
			return
		}
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
	for zwel := range z.DelegationPartition {
		err = en.WriteBytes(z.DelegationPartition[zwel])
		if err != nil {
			return
		}
	}
	// write "E2EESlots"
	err = en.Append(0xa9, 0x45, 0x32, 0x45, 0x45, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.E2EESlots)))
	if err != nil {
		return
	}
	for zrbe := range z.E2EESlots {
		err = en.WriteBytes(z.E2EESlots[zrbe])
		if err != nil {
			return
		}
	}
	// write "e2ee"
	err = en.Append(0xa4, 0x65, 0x32, 0x65, 0x65)
	if err != nil {
		return err
	}
	if z.E2EE == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.E2EE.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *InheritanceMap) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 6
	// string "partitionLabelKey"
	o = append(o, 0x86, 0xb1, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if z.PartitionLabelKey == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.PartitionLabelKey.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "globalLabelKey"
	o = append(o, 0xae, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79)
	if z.GlobalLabelKey == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.GlobalLabelKey.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "delegationKey"
	o = append(o, 0xad, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79)
	if z.DelegationKey == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.DelegationKey.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "delegationPartition"
	o = append(o, 0xb3, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e)
	o = msgp.AppendArrayHeader(o, uint32(len(z.DelegationPartition)))
	for zwel := range z.DelegationPartition {
		o = msgp.AppendBytes(o, z.DelegationPartition[zwel])
	}
	// string "E2EESlots"
	o = append(o, 0xa9, 0x45, 0x32, 0x45, 0x45, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.E2EESlots)))
	for zrbe := range z.E2EESlots {
		o = msgp.AppendBytes(o, z.E2EESlots[zrbe])
	}
	// string "e2ee"
	o = append(o, 0xa4, 0x65, 0x32, 0x65, 0x65)
	if z.E2EE == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.E2EE.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *InheritanceMap) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zbal uint32
	zbal, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zbal > 0 {
		zbal--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "partitionLabelKey":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.PartitionLabelKey = nil
			} else {
				if z.PartitionLabelKey == nil {
					z.PartitionLabelKey = new(oaque.PrivateKey)
				}
				bts, err = z.PartitionLabelKey.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "globalLabelKey":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.GlobalLabelKey = nil
			} else {
				if z.GlobalLabelKey == nil {
					z.GlobalLabelKey = new(oaque.PrivateKey)
				}
				bts, err = z.GlobalLabelKey.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "delegationKey":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.DelegationKey = nil
			} else {
				if z.DelegationKey == nil {
					z.DelegationKey = new(oaque.PrivateKey)
				}
				bts, err = z.DelegationKey.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "delegationPartition":
			var zjqz uint32
			zjqz, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(zjqz) {
				z.DelegationPartition = (z.DelegationPartition)[:zjqz]
			} else {
				z.DelegationPartition = make([][]byte, zjqz)
			}
			for zwel := range z.DelegationPartition {
				z.DelegationPartition[zwel], bts, err = msgp.ReadBytesBytes(bts, z.DelegationPartition[zwel])
				if err != nil {
					return
				}
			}
		case "E2EESlots":
			var zkct uint32
			zkct, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.E2EESlots) >= int(zkct) {
				z.E2EESlots = (z.E2EESlots)[:zkct]
			} else {
				z.E2EESlots = make([][]byte, zkct)
			}
			for zrbe := range z.E2EESlots {
				z.E2EESlots[zrbe], bts, err = msgp.ReadBytesBytes(bts, z.E2EESlots[zrbe])
				if err != nil {
					return
				}
			}
		case "e2ee":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.E2EE = nil
			} else {
				if z.E2EE == nil {
					z.E2EE = new(oaque.PrivateKey)
				}
				bts, err = z.E2EE.UnmarshalMsg(bts)
				if err != nil {
					return
				}
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
	s = 1 + 18
	if z.PartitionLabelKey == nil {
		s += msgp.NilSize
	} else {
		s += z.PartitionLabelKey.Msgsize()
	}
	s += 15
	if z.GlobalLabelKey == nil {
		s += msgp.NilSize
	} else {
		s += z.GlobalLabelKey.Msgsize()
	}
	s += 14
	if z.DelegationKey == nil {
		s += msgp.NilSize
	} else {
		s += z.DelegationKey.Msgsize()
	}
	s += 20 + msgp.ArrayHeaderSize
	for zwel := range z.DelegationPartition {
		s += msgp.BytesPrefixSize + len(z.DelegationPartition[zwel])
	}
	s += 10 + msgp.ArrayHeaderSize
	for zrbe := range z.E2EESlots {
		s += msgp.BytesPrefixSize + len(z.E2EESlots[zrbe])
	}
	s += 5
	if z.E2EE == nil {
		s += msgp.NilSize
	} else {
		s += z.E2EE.Msgsize()
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *OAQUEKey) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var ztmt []byte
		ztmt, err = dc.ReadBytes([]byte((*z)))
		(*z) = OAQUEKey(ztmt)
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
		var ztco []byte
		ztco, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = OAQUEKey(ztco)
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
	var zinl uint32
	zinl, err = dc.ReadArrayHeader()
	if err != nil {
		return
	}
	if cap((*z)) >= int(zinl) {
		(*z) = (*z)[:zinl]
	} else {
		(*z) = make(PartitionLabel, zinl)
	}
	for ztyy := range *z {
		(*z)[ztyy], err = dc.ReadBytes((*z)[ztyy])
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
	for zare := range z {
		err = en.WriteBytes(z[zare])
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
	for zare := range z {
		o = msgp.AppendBytes(o, z[zare])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PartitionLabel) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zixj uint32
	zixj, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		return
	}
	if cap((*z)) >= int(zixj) {
		(*z) = (*z)[:zixj]
	} else {
		(*z) = make(PartitionLabel, zixj)
	}
	for zljy := range *z {
		(*z)[zljy], bts, err = msgp.ReadBytesBytes(bts, (*z)[zljy])
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
	for zrsc := range z {
		s += msgp.BytesPrefixSize + len(z[zrsc])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *PlaintextHeader) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zctn uint32
	zctn, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zctn > 0 {
		zctn--
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
				var zswy []byte
				zswy, err = dc.ReadBytes([]byte(z.SigVK))
				z.SigVK = Ed25519VK(zswy)
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
	var znsg uint32
	znsg, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for znsg > 0 {
		znsg--
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
				var zrus []byte
				zrus, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigVK))
				z.SigVK = Ed25519VK(zrus)
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
