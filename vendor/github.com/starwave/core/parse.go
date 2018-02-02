package core

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const EndOfURISymbol = '$'

func ValidateURIComponent(uri string) bool {
	if len(uri) == 1 && uri[0] == '$' {
		return false
	}
	return true
}

func ParseURIFromPath(uriPath []string) (URIPath, error) {
	if len(uriPath) > MaxURILength {
		return nil, errors.New("URI too long")
	}

	prefix := false
	components := make(URIPath, 0, len(uriPath)+1)
	for i, name := range uriPath {
		if !ValidateURIComponent(name) {
			return nil, fmt.Errorf("'%s' is not a valid URI component", name)
		}
		if name == "*" {
			if i == len(uriPath)-1 {
				prefix = true
			} else {
				return nil, errors.New("Wildcard '*' not allowed in middle of URI")
			}
		} else {
			component := NewURIComponent(name, URIComponentPosition(i))
			components = append(components, component)
		}
	}

	if !prefix {
		terminator := NewURIComponent(string(EndOfURISymbol), URIComponentPosition(len(uriPath)))
		components = append(components, terminator)
	}

	return components, nil
}

func ParseURI(uri string) (URIPath, error) {
	rawComponents := strings.Split(uri, "/")
	filteredComponents := make([]string, 0, len(rawComponents))
	for _, rawComponent := range rawComponents {
		if rawComponent != "" {
			filteredComponents = append(filteredComponents, rawComponent)
		}
	}
	return ParseURIFromPath(filteredComponents)
}

func (ecp TimeComponentPosition) String() string {
	switch ecp {
	case TimeComponentPositionYear:
		return "year"
	case TimeComponentPositionMonth:
		return "month"
	case TimeComponentPositionFiveDays:
		return "fivedays"
	case TimeComponentPositionDay:
		return "day"
	case TimeComponentPositionSixHours:
		return "sixhours"
	case TimeComponentPositionHour:
		return "hour"
	default:
		panic("Invalid expiry component position")
	}
}

func ValidateTimeComponent(prefix TimePath, quantity uint16, position TimeComponentPosition) bool {
	min, max := TimeComponentBounds(prefix, position)
	return min <= quantity && quantity <= max
}

func ParseTimeFromPath(timePath []uint16) (TimePath, error) {
	if len(timePath) > MaxTimeLength {
		return nil, errors.New("Expiry path too long")
	}

	components := make(TimePath, 0, len(timePath))
	for i, quantity := range timePath {
		pos := TimeComponentPosition(i)
		if !ValidateTimeComponent(components, quantity, pos) {
			return nil, fmt.Errorf("'%d' is not a valid %s", quantity, pos.String())
		}
		component := NewTimeComponent(quantity, pos)
		components = append(components, component)
	}
	return components, nil
}

func ParseTime(time time.Time) (TimePath, error) {
	path := make([]uint16, 6, 6)
	path[0] = uint16(time.Year())
	path[1] = uint16(time.Month())
	path[3] = uint16(time.Day())
	path[2] = (path[3]-1)/5 + 1
	if path[2] == 7 {
		path[2] = 6
	}
	path[5] = uint16(time.Hour())
	path[4] = (path[5] / 6) + 1
	return ParseTimeFromPath(path)
}
