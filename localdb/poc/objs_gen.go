package poc

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
	"github.com/tinylib/msgp/msgp"
)

// MarshalMsg implements msgp.Marshaler
func (z *ContentKeyState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "Slots"
	o = append(o, 0x82, 0xa5, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Slots)))
	for zxvk := range z.Slots {
		o = msgp.AppendBytes(o, z.Slots[zxvk])
	}
	// string "Key"
	o = append(o, 0xa3, 0x4b, 0x65, 0x79)
	if z.Key == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Key.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *ContentKeyState) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "Slots":
			var zbai uint32
			zbai, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Slots) >= int(zbai) {
				z.Slots = (z.Slots)[:zbai]
			} else {
				z.Slots = make([][]byte, zbai)
			}
			for zxvk := range z.Slots {
				z.Slots[zxvk], bts, err = msgp.ReadBytesBytes(bts, z.Slots[zxvk])
				if err != nil {
					return
				}
			}
		case "Key":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Key = nil
			} else {
				if z.Key == nil {
					z.Key = new(oaque.PrivateKey)
				}
				bts, err = z.Key.UnmarshalMsg(bts)
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
func (z *ContentKeyState) Msgsize() (s int) {
	s = 1 + 6 + msgp.ArrayHeaderSize
	for zxvk := range z.Slots {
		s += msgp.BytesPrefixSize + len(z.Slots[zxvk])
	}
	s += 4
	if z.Key == nil {
		s += msgp.NilSize
	} else {
		s += z.Key.Msgsize()
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *DotState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "Dot"
	o = append(o, 0x83, 0xa3, 0x44, 0x6f, 0x74)
	if z.Dot == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Dot.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "State"
	o = append(o, 0xa5, 0x53, 0x74, 0x61, 0x74, 0x65)
	o = msgp.AppendInt(o, z.State)
	// string "LabelKeyIndex"
	o = append(o, 0xad, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78)
	o = msgp.AppendInt(o, z.LabelKeyIndex)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *DotState) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "Dot":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Dot = nil
			} else {
				if z.Dot == nil {
					z.Dot = new(dot.DOT)
				}
				bts, err = z.Dot.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "State":
			z.State, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				return
			}
		case "LabelKeyIndex":
			z.LabelKeyIndex, bts, err = msgp.ReadIntBytes(bts)
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
func (z *DotState) Msgsize() (s int) {
	s = 1 + 4
	if z.Dot == nil {
		s += msgp.NilSize
	} else {
		s += z.Dot.Msgsize()
	}
	s += 6 + msgp.IntSize + 14 + msgp.IntSize
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EntityState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 4
	// string "Entity"
	o = append(o, 0x84, 0xa6, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79)
	if z.Entity == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Entity.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "State"
	o = append(o, 0xa5, 0x53, 0x74, 0x61, 0x74, 0x65)
	o = msgp.AppendInt(o, z.State)
	// string "DotIndex"
	o = append(o, 0xa8, 0x44, 0x6f, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78)
	o = msgp.AppendInt(o, z.DotIndex)
	// string "MaxLabelKeyIndex"
	o = append(o, 0xb0, 0x4d, 0x61, 0x78, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78)
	o = msgp.AppendInt(o, z.MaxLabelKeyIndex)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EntityState) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zajw uint32
	zajw, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zajw > 0 {
		zajw--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Entity":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Entity = nil
			} else {
				if z.Entity == nil {
					z.Entity = new(entity.Entity)
				}
				bts, err = z.Entity.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "State":
			z.State, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				return
			}
		case "DotIndex":
			z.DotIndex, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				return
			}
		case "MaxLabelKeyIndex":
			z.MaxLabelKeyIndex, bts, err = msgp.ReadIntBytes(bts)
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
func (z *EntityState) Msgsize() (s int) {
	s = 1 + 7
	if z.Entity == nil {
		s += msgp.NilSize
	} else {
		s += z.Entity.Msgsize()
	}
	s += 6 + msgp.IntSize + 9 + msgp.IntSize + 17 + msgp.IntSize
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *PLKState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "Slots"
	o = append(o, 0x83, 0xa5, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Slots)))
	for zwht := range z.Slots {
		o = msgp.AppendBytes(o, z.Slots[zwht])
	}
	// string "Key"
	o = append(o, 0xa3, 0x4b, 0x65, 0x79)
	if z.Key == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Key.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "Namespace"
	o = append(o, 0xa9, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65)
	o = msgp.AppendBytes(o, z.Namespace)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PLKState) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zhct uint32
	zhct, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zhct > 0 {
		zhct--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Slots":
			var zcua uint32
			zcua, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Slots) >= int(zcua) {
				z.Slots = (z.Slots)[:zcua]
			} else {
				z.Slots = make([][]byte, zcua)
			}
			for zwht := range z.Slots {
				z.Slots[zwht], bts, err = msgp.ReadBytesBytes(bts, z.Slots[zwht])
				if err != nil {
					return
				}
			}
		case "Key":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Key = nil
			} else {
				if z.Key == nil {
					z.Key = new(oaque.PrivateKey)
				}
				bts, err = z.Key.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "Namespace":
			z.Namespace, bts, err = msgp.ReadBytesBytes(bts, z.Namespace)
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
func (z *PLKState) Msgsize() (s int) {
	s = 1 + 6 + msgp.ArrayHeaderSize
	for zwht := range z.Slots {
		s += msgp.BytesPrefixSize + len(z.Slots[zwht])
	}
	s += 4
	if z.Key == nil {
		s += msgp.NilSize
	} else {
		s += z.Key.Msgsize()
	}
	s += 10 + msgp.BytesPrefixSize + len(z.Namespace)
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *PendingLabels) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 1
	// string "Slots"
	o = append(o, 0x81, 0xa5, 0x53, 0x6c, 0x6f, 0x74, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Slots)))
	for zxhx := range z.Slots {
		o = msgp.AppendBytes(o, z.Slots[zxhx])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *PendingLabels) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zlqf uint32
	zlqf, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zlqf > 0 {
		zlqf--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Slots":
			var zdaf uint32
			zdaf, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Slots) >= int(zdaf) {
				z.Slots = (z.Slots)[:zdaf]
			} else {
				z.Slots = make([][]byte, zdaf)
			}
			for zxhx := range z.Slots {
				z.Slots[zxhx], bts, err = msgp.ReadBytesBytes(bts, z.Slots[zxhx])
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
func (z *PendingLabels) Msgsize() (s int) {
	s = 1 + 6 + msgp.ArrayHeaderSize
	for zxhx := range z.Slots {
		s += msgp.BytesPrefixSize + len(z.Slots[zxhx])
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *RevocationState) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "IsEntity"
	o = append(o, 0x82, 0xa8, 0x49, 0x73, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79)
	o = msgp.AppendBool(o, z.IsEntity)
	// string "TargetHash"
	o = append(o, 0xaa, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x48, 0x61, 0x73, 0x68)
	o = msgp.AppendBytes(o, z.TargetHash)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *RevocationState) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zpks uint32
	zpks, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zpks > 0 {
		zpks--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "IsEntity":
			z.IsEntity, bts, err = msgp.ReadBoolBytes(bts)
			if err != nil {
				return
			}
		case "TargetHash":
			z.TargetHash, bts, err = msgp.ReadBytesBytes(bts, z.TargetHash)
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
func (z *RevocationState) Msgsize() (s int) {
	s = 1 + 9 + msgp.BoolSize + 11 + msgp.BytesPrefixSize + len(z.TargetHash)
	return
}
