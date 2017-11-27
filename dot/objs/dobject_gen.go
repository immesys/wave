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
				var zcua uint32
				zcua, err = dc.ReadMapHeader()
				if err != nil {
					return
				}
				for zcua > 0 {
					zcua--
					field, err = dc.ReadMapKeyPtr()
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "dst":
						z.PlaintextHeader.DST, err = dc.ReadBytes(z.PlaintextHeader.DST)
						if err != nil {
							return
						}
					case "rvk":
						z.PlaintextHeader.RevocationHash, err = dc.ReadBytes(z.PlaintextHeader.RevocationHash)
						if err != nil {
							return
						}
					case "sigvk":
						{
							var zxhx []byte
							zxhx, err = dc.ReadBytes([]byte(z.PlaintextHeader.SigVK))
							z.PlaintextHeader.SigVK = Ed25519VK(zxhx)
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
			var zlqf uint32
			zlqf, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zlqf) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zlqf]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zlqf)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], err = dc.ReadBytes(z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "Outersig":
			{
				var zdaf []byte
				zdaf, err = dc.ReadBytes([]byte(z.Outersig))
				z.Outersig = Ed25519Signature(zdaf)
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
			var zpks uint32
			zpks, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.PartitionLabel) >= int(zpks) {
				z.PartitionLabel = (z.PartitionLabel)[:zpks]
			} else {
				z.PartitionLabel = make([][]byte, zpks)
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
		// map header, size 3
		// write "dst"
		err = en.Append(0x83, 0xa3, 0x64, 0x73, 0x74)
		if err != nil {
			return err
		}
		err = en.WriteBytes(z.PlaintextHeader.DST)
		if err != nil {
			return
		}
		// write "rvk"
		err = en.Append(0xa3, 0x72, 0x76, 0x6b)
		if err != nil {
			return err
		}
		err = en.WriteBytes(z.PlaintextHeader.RevocationHash)
		if err != nil {
			return
		}
		// write "sigvk"
		err = en.Append(0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
		if err != nil {
			return err
		}
		err = en.WriteBytes([]byte(z.PlaintextHeader.SigVK))
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
		// map header, size 3
		// string "dst"
		o = append(o, 0x83, 0xa3, 0x64, 0x73, 0x74)
		o = msgp.AppendBytes(o, z.PlaintextHeader.DST)
		// string "rvk"
		o = append(o, 0xa3, 0x72, 0x76, 0x6b)
		o = msgp.AppendBytes(o, z.PlaintextHeader.RevocationHash)
		// string "sigvk"
		o = append(o, 0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
		o = msgp.AppendBytes(o, []byte(z.PlaintextHeader.SigVK))
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
	var zjfb uint32
	zjfb, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zjfb > 0 {
		zjfb--
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
				var zcxo uint32
				zcxo, bts, err = msgp.ReadMapHeaderBytes(bts)
				if err != nil {
					return
				}
				for zcxo > 0 {
					zcxo--
					field, bts, err = msgp.ReadMapKeyZC(bts)
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "dst":
						z.PlaintextHeader.DST, bts, err = msgp.ReadBytesBytes(bts, z.PlaintextHeader.DST)
						if err != nil {
							return
						}
					case "rvk":
						z.PlaintextHeader.RevocationHash, bts, err = msgp.ReadBytesBytes(bts, z.PlaintextHeader.RevocationHash)
						if err != nil {
							return
						}
					case "sigvk":
						{
							var zeff []byte
							zeff, bts, err = msgp.ReadBytesBytes(bts, []byte(z.PlaintextHeader.SigVK))
							z.PlaintextHeader.SigVK = Ed25519VK(zeff)
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
			var zrsw uint32
			zrsw, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zrsw) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zrsw]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zrsw)
			}
			for zajw := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[zajw], bts, err = msgp.ReadBytesBytes(bts, z.ContentAuditorKeyholes[zajw])
				if err != nil {
					return
				}
			}
		case "Outersig":
			{
				var zxpk []byte
				zxpk, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Outersig))
				z.Outersig = Ed25519Signature(zxpk)
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
			var zdnj uint32
			zdnj, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.PartitionLabel) >= int(zdnj) {
				z.PartitionLabel = (z.PartitionLabel)[:zdnj]
			} else {
				z.PartitionLabel = make([][]byte, zdnj)
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
		s += 1 + 4 + msgp.BytesPrefixSize + len(z.PlaintextHeader.DST) + 4 + msgp.BytesPrefixSize + len(z.PlaintextHeader.RevocationHash) + 6 + msgp.BytesPrefixSize + len([]byte(z.PlaintextHeader.SigVK))
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
	var zsnv uint32
	zsnv, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zsnv > 0 {
		zsnv--
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
			var zkgt uint32
			zkgt, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zkgt) {
				z.Permissions = (z.Permissions)[:zkgt]
			} else {
				z.Permissions = make([]string, zkgt)
			}
			for zobc := range z.Permissions {
				z.Permissions[zobc], err = dc.ReadString()
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
				var zema []byte
				zema, err = dc.ReadBytes([]byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zema)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zpez []byte
				zpez, err = dc.ReadBytes([]byte(z.Signature))
				z.Signature = Ed25519Signature(zpez)
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
	for zobc := range z.Permissions {
		err = en.WriteString(z.Permissions[zobc])
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
	for zobc := range z.Permissions {
		o = msgp.AppendString(o, z.Permissions[zobc])
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
	var zqke uint32
	zqke, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zqke > 0 {
		zqke--
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
			var zqyh uint32
			zqyh, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Permissions) >= int(zqyh) {
				z.Permissions = (z.Permissions)[:zqyh]
			} else {
				z.Permissions = make([]string, zqyh)
			}
			for zobc := range z.Permissions {
				z.Permissions[zobc], bts, err = msgp.ReadStringBytes(bts)
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
				var zyzr []byte
				zyzr, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigningVK))
				z.SigningVK = Ed25519VK(zyzr)
			}
			if err != nil {
				return
			}
		case "signature":
			{
				var zywj []byte
				zywj, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Signature))
				z.Signature = Ed25519Signature(zywj)
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
	for zobc := range z.Permissions {
		s += msgp.StringPrefixSize + len(z.Permissions[zobc])
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
		var zjpj []byte
		zjpj, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519Signature(zjpj)
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
		var zzpf []byte
		zzpf, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519Signature(zzpf)
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
		var zrfe []byte
		zrfe, err = dc.ReadBytes([]byte((*z)))
		(*z) = Ed25519VK(zrfe)
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
		var zgmo []byte
		zgmo, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = Ed25519VK(zgmo)
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
	var zeth uint32
	zeth, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zeth > 0 {
		zeth--
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
				var zsbz uint32
				zsbz, err = dc.ReadMapHeader()
				if err != nil {
					return
				}
				for zsbz > 0 {
					zsbz--
					field, err = dc.ReadMapKeyPtr()
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "dst":
						z.PlaintextHeader.DST, err = dc.ReadBytes(z.PlaintextHeader.DST)
						if err != nil {
							return
						}
					case "rvk":
						z.PlaintextHeader.RevocationHash, err = dc.ReadBytes(z.PlaintextHeader.RevocationHash)
						if err != nil {
							return
						}
					case "sigvk":
						{
							var zrjx []byte
							zrjx, err = dc.ReadBytes([]byte(z.PlaintextHeader.SigVK))
							z.PlaintextHeader.SigVK = Ed25519VK(zrjx)
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
			var zawn uint32
			zawn, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zawn) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zawn]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zawn)
			}
			for ztaf := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[ztaf], err = dc.ReadBytes(z.ContentAuditorKeyholes[ztaf])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zwel []byte
				zwel, err = dc.ReadBytes([]byte(z.Outersig))
				z.Outersig = Ed25519Signature(zwel)
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
		// map header, size 3
		// write "dst"
		err = en.Append(0x83, 0xa3, 0x64, 0x73, 0x74)
		if err != nil {
			return err
		}
		err = en.WriteBytes(z.PlaintextHeader.DST)
		if err != nil {
			return
		}
		// write "rvk"
		err = en.Append(0xa3, 0x72, 0x76, 0x6b)
		if err != nil {
			return err
		}
		err = en.WriteBytes(z.PlaintextHeader.RevocationHash)
		if err != nil {
			return
		}
		// write "sigvk"
		err = en.Append(0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
		if err != nil {
			return err
		}
		err = en.WriteBytes([]byte(z.PlaintextHeader.SigVK))
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
	for ztaf := range z.ContentAuditorKeyholes {
		err = en.WriteBytes(z.ContentAuditorKeyholes[ztaf])
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
		// map header, size 3
		// string "dst"
		o = append(o, 0x83, 0xa3, 0x64, 0x73, 0x74)
		o = msgp.AppendBytes(o, z.PlaintextHeader.DST)
		// string "rvk"
		o = append(o, 0xa3, 0x72, 0x76, 0x6b)
		o = msgp.AppendBytes(o, z.PlaintextHeader.RevocationHash)
		// string "sigvk"
		o = append(o, 0xa5, 0x73, 0x69, 0x67, 0x76, 0x6b)
		o = msgp.AppendBytes(o, []byte(z.PlaintextHeader.SigVK))
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
	for ztaf := range z.ContentAuditorKeyholes {
		o = msgp.AppendBytes(o, z.ContentAuditorKeyholes[ztaf])
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
	var zrbe uint32
	zrbe, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zrbe > 0 {
		zrbe--
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
				var zmfd uint32
				zmfd, bts, err = msgp.ReadMapHeaderBytes(bts)
				if err != nil {
					return
				}
				for zmfd > 0 {
					zmfd--
					field, bts, err = msgp.ReadMapKeyZC(bts)
					if err != nil {
						return
					}
					switch msgp.UnsafeString(field) {
					case "dst":
						z.PlaintextHeader.DST, bts, err = msgp.ReadBytesBytes(bts, z.PlaintextHeader.DST)
						if err != nil {
							return
						}
					case "rvk":
						z.PlaintextHeader.RevocationHash, bts, err = msgp.ReadBytesBytes(bts, z.PlaintextHeader.RevocationHash)
						if err != nil {
							return
						}
					case "sigvk":
						{
							var zzdc []byte
							zzdc, bts, err = msgp.ReadBytesBytes(bts, []byte(z.PlaintextHeader.SigVK))
							z.PlaintextHeader.SigVK = Ed25519VK(zzdc)
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
			var zelx uint32
			zelx, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.ContentAuditorKeyholes) >= int(zelx) {
				z.ContentAuditorKeyholes = (z.ContentAuditorKeyholes)[:zelx]
			} else {
				z.ContentAuditorKeyholes = make([][]byte, zelx)
			}
			for ztaf := range z.ContentAuditorKeyholes {
				z.ContentAuditorKeyholes[ztaf], bts, err = msgp.ReadBytesBytes(bts, z.ContentAuditorKeyholes[ztaf])
				if err != nil {
					return
				}
			}
		case "osig":
			{
				var zbal []byte
				zbal, bts, err = msgp.ReadBytesBytes(bts, []byte(z.Outersig))
				z.Outersig = Ed25519Signature(zbal)
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
		s += 1 + 4 + msgp.BytesPrefixSize + len(z.PlaintextHeader.DST) + 4 + msgp.BytesPrefixSize + len(z.PlaintextHeader.RevocationHash) + 6 + msgp.BytesPrefixSize + len([]byte(z.PlaintextHeader.SigVK))
	}
	s += 8 + msgp.BytesPrefixSize + len(z.EncryptedContent) + 12 + msgp.BytesPrefixSize + len(z.EncryptedInheritance) + 10 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabel) + 8 + msgp.BytesPrefixSize + len(z.EncryptedPartitionLabelKey) + 9 + msgp.BytesPrefixSize + len(z.EncryptedDirectPartLabelKey) + 18 + msgp.BytesPrefixSize + len(z.DelegationKeyhole) + 16 + msgp.ArrayHeaderSize
	for ztaf := range z.ContentAuditorKeyholes {
		s += msgp.BytesPrefixSize + len(z.ContentAuditorKeyholes[ztaf])
	}
	s += 5 + msgp.BytesPrefixSize + len([]byte(z.Outersig))
	return
}

// DecodeMsg implements msgp.Decodable
func (z *HIBEKEY) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zjqz []byte
		zjqz, err = dc.ReadBytes([]byte((*z)))
		(*z) = HIBEKEY(zjqz)
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
		var zkct []byte
		zkct, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = HIBEKEY(zkct)
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
			var ztyy uint32
			ztyy, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(ztyy) {
				z.DelegationPartition = (z.DelegationPartition)[:ztyy]
			} else {
				z.DelegationPartition = make([][]byte, ztyy)
			}
			for ztmt := range z.DelegationPartition {
				z.DelegationPartition[ztmt], err = dc.ReadBytes(z.DelegationPartition[ztmt])
				if err != nil {
					return
				}
			}
		case "E2EESlots":
			var zinl uint32
			zinl, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.E2EESlots) >= int(zinl) {
				z.E2EESlots = (z.E2EESlots)[:zinl]
			} else {
				z.E2EESlots = make([][]byte, zinl)
			}
			for ztco := range z.E2EESlots {
				z.E2EESlots[ztco], err = dc.ReadBytes(z.E2EESlots[ztco])
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
	for ztmt := range z.DelegationPartition {
		err = en.WriteBytes(z.DelegationPartition[ztmt])
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
	for ztco := range z.E2EESlots {
		err = en.WriteBytes(z.E2EESlots[ztco])
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
	for ztmt := range z.DelegationPartition {
		o = msgp.AppendBytes(o, z.DelegationPartition[ztmt])
	}
	// string "E2EESlots"
	o = append(o, 0xa9, 0x45, 0x32, 0x45, 0x45, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.E2EESlots)))
	for ztco := range z.E2EESlots {
		o = msgp.AppendBytes(o, z.E2EESlots[ztco])
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
	var zare uint32
	zare, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zare > 0 {
		zare--
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
			var zljy uint32
			zljy, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.DelegationPartition) >= int(zljy) {
				z.DelegationPartition = (z.DelegationPartition)[:zljy]
			} else {
				z.DelegationPartition = make([][]byte, zljy)
			}
			for ztmt := range z.DelegationPartition {
				z.DelegationPartition[ztmt], bts, err = msgp.ReadBytesBytes(bts, z.DelegationPartition[ztmt])
				if err != nil {
					return
				}
			}
		case "E2EESlots":
			var zixj uint32
			zixj, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.E2EESlots) >= int(zixj) {
				z.E2EESlots = (z.E2EESlots)[:zixj]
			} else {
				z.E2EESlots = make([][]byte, zixj)
			}
			for ztco := range z.E2EESlots {
				z.E2EESlots[ztco], bts, err = msgp.ReadBytesBytes(bts, z.E2EESlots[ztco])
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
	for ztmt := range z.DelegationPartition {
		s += msgp.BytesPrefixSize + len(z.DelegationPartition[ztmt])
	}
	s += 10 + msgp.ArrayHeaderSize
	for ztco := range z.E2EESlots {
		s += msgp.BytesPrefixSize + len(z.E2EESlots[ztco])
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
		var zrsc []byte
		zrsc, err = dc.ReadBytes([]byte((*z)))
		(*z) = OAQUEKey(zrsc)
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
		var zctn []byte
		zctn, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = OAQUEKey(zctn)
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
	var zrus uint32
	zrus, err = dc.ReadArrayHeader()
	if err != nil {
		return
	}
	if cap((*z)) >= int(zrus) {
		(*z) = (*z)[:zrus]
	} else {
		(*z) = make(PartitionLabel, zrus)
	}
	for znsg := range *z {
		(*z)[znsg], err = dc.ReadBytes((*z)[znsg])
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
	for zsvm := range z {
		err = en.WriteBytes(z[zsvm])
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
	for zsvm := range z {
		o = msgp.AppendBytes(o, z[zsvm])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PartitionLabel) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zfzb uint32
	zfzb, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		return
	}
	if cap((*z)) >= int(zfzb) {
		(*z) = (*z)[:zfzb]
	} else {
		(*z) = make(PartitionLabel, zfzb)
	}
	for zaoz := range *z {
		(*z)[zaoz], bts, err = msgp.ReadBytesBytes(bts, (*z)[zaoz])
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
	for zsbo := range z {
		s += msgp.BytesPrefixSize + len(z[zsbo])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *PlaintextHeader) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zjif uint32
	zjif, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zjif > 0 {
		zjif--
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
				var zqgz []byte
				zqgz, err = dc.ReadBytes([]byte(z.SigVK))
				z.SigVK = Ed25519VK(zqgz)
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
	var zsnw uint32
	zsnw, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zsnw > 0 {
		zsnw--
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
				var ztls []byte
				ztls, bts, err = msgp.ReadBytesBytes(bts, []byte(z.SigVK))
				z.SigVK = Ed25519VK(ztls)
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
