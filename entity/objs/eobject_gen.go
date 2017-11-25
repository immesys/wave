package objs

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
		case "sk":
			z.SK, err = dc.ReadBytes(z.SK)
			if err != nil {
				return
			}
		case "mk":
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
	// map header, size 5
	// write "vk"
	err = en.Append(0x85, 0xa2, 0x76, 0x6b)
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
	// write "sk"
	err = en.Append(0xa2, 0x73, 0x6b)
	if err != nil {
		return err
	}
	err = en.WriteBytes(z.SK)
	if err != nil {
		return
	}
	// write "mk"
	err = en.Append(0xa2, 0x6d, 0x6b)
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
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Entity) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 5
	// string "vk"
	o = append(o, 0x85, 0xa2, 0x76, 0x6b)
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
	// string "sk"
	o = append(o, 0xa2, 0x73, 0x6b)
	o = msgp.AppendBytes(o, z.SK)
	// string "mk"
	o = append(o, 0xa2, 0x6d, 0x6b)
	if z.MasterKey == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.MasterKey.MarshalMsg(o)
		if err != nil {
			return
		}
	}
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
		case "sk":
			z.SK, bts, err = msgp.ReadBytesBytes(bts, z.SK)
			if err != nil {
				return
			}
		case "mk":
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
	s = 1 + 3 + msgp.BytesPrefixSize + len(z.VK) + 7
	if z.Params == nil {
		s += msgp.NilSize
	} else {
		s += z.Params.Msgsize()
	}
	s += 6 + msgp.BytesPrefixSize + len(z.RevocationHash) + 3 + msgp.BytesPrefixSize + len(z.SK) + 3
	if z.MasterKey == nil {
		s += msgp.NilSize
	} else {
		s += z.MasterKey.Msgsize()
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EntityHash) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zbai []byte
		zbai, err = dc.ReadBytes([]byte((*z)))
		(*z) = EntityHash(zbai)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z EntityHash) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteBytes([]byte(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z EntityHash) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, []byte(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EntityHash) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zcmr []byte
		zcmr, bts, err = msgp.ReadBytesBytes(bts, []byte((*z)))
		(*z) = EntityHash(zcmr)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z EntityHash) Msgsize() (s int) {
	s = msgp.BytesPrefixSize + len([]byte(z))
	return
}
