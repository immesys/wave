package core

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

/* ID Component Interface */

type IDComponentType int

const (
	URIComponentType IDComponentType = iota
	TimeComponentType
)

type IDComponent interface {
	Type() IDComponentType
	Representation() []byte
	String() string

	// These functions are useful if you don't want to use a type assertion
	// but know what the underlying type is.
	Name() string
	Quantity() uint16
}

/* URI Component */

type URIComponentPosition uint8

const MaxURILength = 14

type URIComponent []byte

func NewURIComponent(name string, position URIComponentPosition) URIComponent {
	uclength := 1 + len(name)
	uc := make([]byte, uclength, uclength)
	uc[0] = byte(position)
	copy(uc[1:], name)
	return uc
}

func (uc URIComponent) Type() IDComponentType {
	return URIComponentType
}

func (uc URIComponent) Representation() []byte {
	return uc
}

func (uc URIComponent) String() string {
	return uc.Name()
}

func (uc URIComponent) Name() string {
	return string(uc[1:])
}

func (uc URIComponent) Quantity() uint16 {
	panic("Quantity() is not a valid method for a URI component")
}

func (uc URIComponent) Position() URIComponentPosition {
	return URIComponentPosition(uc[0])
}

type URIPath []URIComponent

func (up URIPath) String() string {
	components := make([]string, len(up), len(up))
	for i := 0; i != len(components); i++ {
		components[i] = up[i].String()
	}
	return strings.Join(components, "/")
}

func (up URIPath) ID() ID {
	id := make(ID, len(up), len(up))
	for i := 0; i != len(id); i++ {
		id[0] = up[0]
	}
	return id
}

func IsURIPrefix(up1 URIPath, up2 URIPath) bool {
	if len(up1) > len(up2) {
		return false
	}

	for i, comp := range up1 {
		if !bytes.Equal(comp.Representation(), up2[i].Representation()) {
			return false
		}
	}

	return true
}

/* Time Component */

// We divide time into components as follows:
// Year
// Month (always twelve per year)
// Five-Day Periods (always six per month, last one may be shorter or longer)
// Day (always five per five-day period)
// Six-Hour Periods (always four per day)
//
// For example, 16 Feb 2017 at 5 PM is represented as follows:
// 2017/02/3/16/2/17
// 2017 represents year 2017
// 02 represents February
// 3 represents five-day period starting on the 16th
// 16 represents day 16
// 2 represents six-hour period starting at noon
// 17 represents day 17

type TimeComponentPosition uint8

const MaxTimeLength = 6

const (
	TimeComponentPositionYear TimeComponentPosition = iota
	TimeComponentPositionMonth
	TimeComponentPositionFiveDays
	TimeComponentPositionDay
	TimeComponentPositionSixHours
	TimeComponentPositionHour
)

const MinYear = 2015
const MaxYear = 2050

const MinMonth = 1
const MaxMonth = 12

const MinFiveDays = 1
const MaxFiveDays = 6

const MinDay = 1
const MaxDay = 31
const MaxDayShortMonth = 30
const MaxDayFebruary = 28
const MaxDayFebruaryLeapYear = 29

const MinSixHours = 1
const MaxSixHours = 4

const MinHour = 0
const MaxHour = 23

func TimeComponentBounds(prefix TimePath, position TimeComponentPosition) (uint16, uint16) {
	switch position {
	case TimeComponentPositionYear:
		return MinYear, MaxYear
	case TimeComponentPositionMonth:
		return MinMonth, MaxMonth
	case TimeComponentPositionFiveDays:
		return MinFiveDays, MaxFiveDays
	case TimeComponentPositionDay:
		fivedays := prefix[TimeComponentPositionFiveDays].Quantity()
		if fivedays == 6 {
			switch time.Month(prefix[TimeComponentPositionMonth].Quantity()) {
			case time.January:
				fallthrough
			case time.March:
				fallthrough
			case time.May:
				fallthrough
			case time.July:
				fallthrough
			case time.August:
				fallthrough
			case time.October:
				fallthrough
			case time.December:
				return 26, MaxDay
			case time.April:
				fallthrough
			case time.June:
				fallthrough
			case time.September:
				fallthrough
			case time.November:
				return 26, MaxDayShortMonth
			case time.February:
				year := prefix[TimeComponentPositionYear].Quantity()
				if year%4 == 0 && (year%100 != 0 || (year%400 == 0)) {
					return 26, MaxDayFebruaryLeapYear
				}
				return 26, MaxDayFebruary
			}
		}
		return 5*(fivedays-1) + 1, 5 * fivedays
	case TimeComponentPositionSixHours:
		return MinSixHours, MaxSixHours
	case TimeComponentPositionHour:
		sixhours := prefix[TimeComponentPositionSixHours].Quantity()
		return 6 * (sixhours - 1), 6*sixhours - 1
	default:
		panic("Invalid position")
	}
}

type TimeComponent []byte

func NewTimeComponent(quantity uint16, position TimeComponentPosition) TimeComponent {
	tc := []byte{uint8(position), 0, 0}
	binary.LittleEndian.PutUint16(tc[1:3], quantity)
	return tc
}

func (tc TimeComponent) Type() IDComponentType {
	return TimeComponentType
}

func (tc TimeComponent) Representation() []byte {
	return tc
}

func (tc TimeComponent) String() string {
	return strconv.FormatInt(int64(tc.Quantity()), 10)
}

func (tc TimeComponent) Name() string {
	panic("Name() is not a valid method for a Time component")
}

func (tc TimeComponent) Quantity() uint16 {
	return binary.LittleEndian.Uint16(tc[1:3])
}

func (tc TimeComponent) Position() TimeComponentPosition {
	return TimeComponentPosition(tc[0])
}

type TimePath []TimeComponent

func (tp TimePath) String() string {
	components := make([]string, len(tp), len(tp))
	for i := 0; i != len(components); i++ {
		components[i] = tp[i].String()
	}
	return strings.Join(components, "/")
}

func (tp TimePath) ID() ID {
	id := make(ID, len(tp), len(tp))
	for i := 0; i != len(id); i++ {
		id[0] = tp[0]
	}
	return id
}

func IsTimePrefix(tp1 TimePath, tp2 TimePath) bool {
	if len(tp1) > len(tp2) {
		return false
	}

	for i, comp := range tp1 {
		if !bytes.Equal(comp.Representation(), tp2[i].Representation()) {
			return false
		}
	}

	return true
}

/* ID */

type ID []IDComponent

func (id ID) HashToZp() []*big.Int {
	hashed := make([]*big.Int, len(id), len(id))
	for i := 0; i != len(id); i++ {
		hashed[i] = cryptutils.HashToZp(id[i].Representation())
	}
	return hashed
}

// AttributeSetFromIDs converts a URI and time to an OAQUE attribute set.
func AttributeSetFromPaths(uriPath URIPath, timePath TimePath) map[oaque.AttributeIndex]*big.Int {
	attrs := make(map[oaque.AttributeIndex]*big.Int)
	for i, uriComponent := range uriPath {
		attrs[oaque.AttributeIndex(i)] = cryptutils.HashToZp(uriComponent.Representation())
	}
	for j, timeComponent := range timePath {
		attrs[oaque.AttributeIndex(j+MaxURILength)] = cryptutils.HashToZp(timeComponent.Representation())
	}
	return attrs
}

func (id ID) String() string {
	components := make([]string, len(id), len(id))
	for i := 0; i != len(components); i++ {
		components[i] = id[i].String()
	}
	return strings.Join(components, "/")
}

/* Some useful functions. */

// SeparateID splits an ID into two separate IDs, one containing URI components
// the other containing time components.
func SeparateID(id ID) (ID, ID) {
	uriComponents := make(ID, 0, len(id))
	timeComponents := make(ID, 0, len(id))
	for _, component := range id {
		switch component.Type() {
		case URIComponentType:
			uriComponents = append(uriComponents, component)
		case TimeComponentType:
			timeComponents = append(timeComponents, component)
		default:
			panic("Unknown ID component type")
		}
	}
	return uriComponents, timeComponents
}

// JoinIDs joins two IDs by concatenation. For example, given a slice of URI
// components and a slice of Time components, one can combine them using this
// function. It does not change the position value inside each component.
func JoinIDs(first ID, second ID) ID {
	combined := make(ID, 0, len(first)+len(second))
	combined = append(combined, first...)
	combined = append(combined, second...)
	return combined
}

// URIToBytes marshals a URIPath into a string of bytes.
func URIToBytes(up URIPath) []byte {
	length := 0
	for _, component := range up {
		length += len(component)
	}

	buf := make([]byte, 1+length+len(up))
	buf[0] = byte(len(up))
	start := 1
	for _, component := range up {
		rep := component
		copy(buf[start:], rep)
		buf[start+len(rep)] = 255
		start += len(rep) + 1
	}
	return buf
}

// TimeToBytes marshals a TimePath into a string of bytes.
func TimeToBytes(tp TimePath) []byte {
	length := 0
	for _, component := range tp {
		length += len(component)
	}

	bytelen := 2*length + 1
	if length == 0 {
		bytelen--
	}

	buf := make([]byte, 1+bytelen)
	buf[0] = byte(len(tp))
	start := 1
	for _, component := range tp {
		copy(buf[start:start+3], component)
		start += 3
	}
	return buf
}

// URIFromBytes unmarshals a URIPath from a string of bytes marshalled with
// IDToBytes.
func URIFromBytes(marshalled []byte) URIPath {
	num := marshalled[0]
	up := make(URIPath, num)

	compidx := 0
	start := 1
	for i := 1; i != len(marshalled); i++ {
		if marshalled[i] == 255 {
			up[compidx] = marshalled[start:i]
			start = i + 1
			compidx++
		}
	}
	return up
}

// TimeFromBytes unmarshals a TimePath from a string of bytes marshalled with
// IDToBytes.
func TimeFromBytes(marshalled []byte) TimePath {
	num := marshalled[0]
	tp := make(TimePath, num)

	start := 1
	for idx := range tp {
		tp[idx] = marshalled[start : start+3]
		start += 3
	}

	return tp
}
