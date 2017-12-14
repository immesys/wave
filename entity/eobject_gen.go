package entity

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *Entity) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zxvk uint32
	zxvk, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zxvk > 0 {
		zxvk--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "PrimaryLocation":
			z.PrimaryLocation, err = dc.ReadString()
			if err != nil {
				return
			}
		case "VK":
			z.VK, err = dc.ReadBytes(z.VK)
			if err != nil {
				return
			}
		case "Params":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Params = nil
			} else {
				if z.Params == nil {
					z.Params = new(oaque.Params)
				}
				err = z.Params.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "RevocationHash":
			z.RevocationHash, err = dc.ReadBytes(z.RevocationHash)
			if err != nil {
				return
			}
		case "Expiry":
			z.Expiry, err = dc.ReadInt64()
			if err != nil {
				return
			}
		case "SK":
			z.SK, err = dc.ReadBytes(z.SK)
			if err != nil {
				return
			}
		case "MasterKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.MasterKey = nil
			} else {
				if z.MasterKey == nil {
					z.MasterKey = new(oaque.MasterKey)
				}
				err = z.MasterKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "Hash":
			z.Hash, err = dc.ReadBytes(z.Hash)
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
func (z *Entity) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 8
	// write "PrimaryLocation"
	err = en.Append(0x88, 0xaf, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e)
	if err != nil {
		return err
	}
	err = en.WriteString(z.PrimaryLocation)
	if err != nil {
		return
	}
	// write "VK"
	err = en.Append(0xa2, 0x56, 0x4b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.VK)
	if err != nil {
		return
	}
	// write "Params"
	err = en.Append(0xa6, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	if z.Params == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Params.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "RevocationHash"
	err = en.Append(0xae, 0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x61, 0x73, 0x68)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.RevocationHash)
	if err != nil {
		return
	}
	// write "Expiry"
	err = en.Append(0xa6, 0x45, 0x78, 0x70, 0x69, 0x72, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.Expiry)
	if err != nil {
		return
	}
	// write "SK"
	err = en.Append(0xa2, 0x53, 0x4b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.SK)
	if err != nil {
		return
	}
	// write "MasterKey"
	err = en.Append(0xa9, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.MasterKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.MasterKey.EncodeMsg(en)
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
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Entity) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 8
	// string "PrimaryLocation"
	o = append(o, 0x88, 0xaf, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e)
	o = msgp.AppendString(o, z.PrimaryLocation)
	// string "VK"
	o = append(o, 0xa2, 0x56, 0x4b)
	o = msgp.AppendBytes(o, z.VK)
	// string "Params"
	o = append(o, 0xa6, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if z.Params == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Params.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "RevocationHash"
	o = append(o, 0xae, 0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x61, 0x73, 0x68)
	o = msgp.AppendBytes(o, z.RevocationHash)
	// string "Expiry"
	o = append(o, 0xa6, 0x45, 0x78, 0x70, 0x69, 0x72, 0x79)
	o = msgp.AppendInt64(o, z.Expiry)
	// string "SK"
	o = append(o, 0xa2, 0x53, 0x4b)
	o = msgp.AppendBytes(o, z.SK)
	// string "MasterKey"
	o = append(o, 0xa9, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x4b, 0x65, 0x79)
	if z.MasterKey == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.MasterKey.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "Hash"
	o = append(o, 0xa4, 0x48, 0x61, 0x73, 0x68)
	o = msgp.AppendBytes(o, z.Hash)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Entity) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zbzg uint32
	zbzg, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zbzg > 0 {
		zbzg--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "PrimaryLocation":
			z.PrimaryLocation, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "VK":
			z.VK, bts, err = msgp.ReadBytesBytes(bts, z.VK)
			if err != nil {
				return
			}
		case "Params":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Params = nil
			} else {
				if z.Params == nil {
					z.Params = new(oaque.Params)
				}
				bts, err = z.Params.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "RevocationHash":
			z.RevocationHash, bts, err = msgp.ReadBytesBytes(bts, z.RevocationHash)
			if err != nil {
				return
			}
		case "Expiry":
			z.Expiry, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "SK":
			z.SK, bts, err = msgp.ReadBytesBytes(bts, z.SK)
			if err != nil {
				return
			}
		case "MasterKey":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.MasterKey = nil
			} else {
				if z.MasterKey == nil {
					z.MasterKey = new(oaque.MasterKey)
				}
				bts, err = z.MasterKey.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "Hash":
			z.Hash, bts, err = msgp.ReadBytesBytes(bts, z.Hash)
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
func (z *Entity) Msgsize() (s int) {
	s = 1 + 16 + msgp.StringPrefixSize + len(z.PrimaryLocation) + 3 + msgp.BytesPrefixSize + len(z.VK) + 7
	if z.Params == nil {
		s += msgp.NilSize
	} else {
		s += z.Params.Msgsize()
	}
	s += 15 + msgp.BytesPrefixSize + len(z.RevocationHash) + 7 + msgp.Int64Size + 3 + msgp.BytesPrefixSize + len(z.SK) + 10
	if z.MasterKey == nil {
		s += msgp.NilSize
	} else {
		s += z.MasterKey.Msgsize()
	}
	s += 5 + msgp.BytesPrefixSize + len(z.Hash)
	return
}

// DecodeMsg implements msgp.Decodable
func (z *ExternalEntity) DecodeMsg(dc *msgp.Reader) (err error) {
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
		case "vk":
			z.VK, err = dc.ReadBytes(z.VK)
			if err != nil {
				return
			}
		case "params":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Params = nil
			} else {
				if z.Params == nil {
					z.Params = new(oaque.Params)
				}
				err = z.Params.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "rhash":
			z.RevocationHash, err = dc.ReadBytes(z.RevocationHash)
			if err != nil {
				return
			}
		case "expiry":
			z.Expiry, err = dc.ReadInt64()
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
func (z *ExternalEntity) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 4
	// write "vk"
	err = en.Append(0x84, 0xa2, 0x76, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.VK)
	if err != nil {
		return
	}
	// write "params"
	err = en.Append(0xa6, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	if z.Params == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Params.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "rhash"
	err = en.Append(0xa5, 0x72, 0x68, 0x61, 0x73, 0x68)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.RevocationHash)
	if err != nil {
		return
	}
	// write "expiry"
	err = en.Append(0xa6, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79)
	if err != nil {
		return err
	}
	err = en.WriteInt64(z.Expiry)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *ExternalEntity) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 4
	// string "vk"
	o = append(o, 0x84, 0xa2, 0x76, 0x6b)
	o = msgp.AppendBytes(o, z.VK)
	// string "params"
	o = append(o, 0xa6, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if z.Params == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Params.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "rhash"
	o = append(o, 0xa5, 0x72, 0x68, 0x61, 0x73, 0x68)
	o = msgp.AppendBytes(o, z.RevocationHash)
	// string "expiry"
	o = append(o, 0xa6, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79)
	o = msgp.AppendInt64(o, z.Expiry)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *ExternalEntity) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "vk":
			z.VK, bts, err = msgp.ReadBytesBytes(bts, z.VK)
			if err != nil {
				return
			}
		case "params":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Params = nil
			} else {
				if z.Params == nil {
					z.Params = new(oaque.Params)
				}
				bts, err = z.Params.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "rhash":
			z.RevocationHash, bts, err = msgp.ReadBytesBytes(bts, z.RevocationHash)
			if err != nil {
				return
			}
		case "expiry":
			z.Expiry, bts, err = msgp.ReadInt64Bytes(bts)
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
func (z *ExternalEntity) Msgsize() (s int) {
	s = 1 + 3 + msgp.BytesPrefixSize + len(z.VK) + 7
	if z.Params == nil {
		s += msgp.NilSize
	} else {
		s += z.Params.Msgsize()
	}
	s += 6 + msgp.BytesPrefixSize + len(z.RevocationHash) + 7 + msgp.Int64Size
	return
}
