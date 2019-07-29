package jediutils

import (
	"fmt"

	"github.com/ucbrise/jedi-protocol-go"
)

// WAVEPatternEncoder implements the jedi.PatternEncoder interface. It
// represents the algorithm to encode JEDI patterns in a way that is compatible
// with WAVE's attestations and WAVE's other uses of WKD-IBE.
type WAVEPatternEncoder struct{}

// WAVEPatternEncoderSingleton is a single instance of WAVEPatternEncoder that
// is meant to be used globally. This is possible because WAVEPatternEncoder
// keeps absolutely no state.
var WAVEPatternEncoderSingleton *WAVEPatternEncoder

// Encode encodes a URI path and time path into a JEDI pattern in a way that is
// compatible with WAVE's attestations and WAVE's other uses of WKD-IBE.
func (wpe *WAVEPatternEncoder) Encode(uriPath jedi.URIPath, timePath jedi.TimePath, patternType jedi.PatternType) jedi.Pattern {
	pattern := make(jedi.Pattern, 20)
	switch patternType {
	case jedi.PatternTypeDecryption:
		pattern[0] = []byte("\x00jedi:decrypt")
	case jedi.PatternTypeSigning:
		pattern[0] = []byte("\x00jedi:sign")
	default:
		panic(fmt.Sprintf("Unknown key type %d\n", patternType))
	}
	jedi.EncodePattern(uriPath, timePath, pattern[1:])
	return pattern
}
