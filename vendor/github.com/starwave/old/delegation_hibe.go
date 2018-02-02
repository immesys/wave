package core

import (
	"bytes"
	"fmt"
	"io"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/hibe"
	"golang.org/x/crypto/sha3"
)

// SeedTopLevel generates a private key with the full privilege of the master
// key. It accepts a reader that should provide the randomness with which to
// generate this key from the master key. Generation of all descendants from
// this key is deterministic; therefore, the randomness in choosing to master
// key, and the randomness provided to this function, together script the
// randomness for the entire HIBE hierarchy.
func CreateTopLevel(random io.Reader, params *hibe.Params, masterKey hibe.MasterKey) *hibe.PrivateKey {
	key, err := hibe.KeyGenFromMaster(random, params, masterKey, []*big.Int{})
	if err != nil {
		panic(err)
	}
	return key
}

// GenerateChild generates the HIBE secret key for an ID, given the private key
// for its parent. Key generation is done deterministically, in order to avoid
// problems with reusing garbled circuits for out-of-order delegation.
func GenerateChild(params *hibe.Params, key *hibe.PrivateKey, childID ID) *hibe.PrivateKey {
	shake := sha3.NewShake256()
	keyBytes := key.Marshal()
	_, err := shake.Write(keyBytes)
	if err != nil {
		panic(err)
	}
	childKey, err := hibe.KeyGenFromParent(shake, params, key, childID.HashToZp())
	if err != nil {
		panic(err)
	}
	return childKey
}

// GenerateDescendant generates a "subkey" for a specified URI (or URI prefix)
// and time (or time prefix). If the provided parent ID cannot be used to
// generate a key with the desired URI and time, this function returns an error
// (for example, if the parent ID is not a prefix of the desired URI prefix).
// Otherwise, it deterministically generates the key for the desired URI and
// time, and returns the key and the ID to which it corresponds.
func GenerateDescendant(params *hibe.Params, parentKey *hibe.PrivateKey, parentID ID, desiredURI ID, desiredTime ID) (ID, *hibe.PrivateKey, error) {
	/*
	 * First, do some validation work, to make sure that the arguments are
	 * valid. While we're at it, we also find the index in the desired URI and
	 * time which are not already in the ID (i.e., which we have to generate).
	 */
	uriSuffixStart := 0
	timeSuffixStart := 0
	for _, component := range parentID {
		switch component.Type() {
		case URIComponentType:
			if uriSuffixStart == len(desiredURI) || !bytes.Equal(desiredURI[uriSuffixStart].Representation(), component.Representation()) {
				return nil, nil, fmt.Errorf("Key for URI %s is not computable from %s", desiredURI, parentID)
			}
			uriSuffixStart++
		case TimeComponentType:
			if timeSuffixStart == len(desiredTime) || !bytes.Equal(desiredTime[timeSuffixStart].Representation(), component.Representation()) {
				return nil, nil, fmt.Errorf("Key for time %s is not computable from %s", desiredTime, parentID)
			}
			timeSuffixStart++
		default:
			panic("Unknown ID component type")
		}
	}

	uriSuffix := desiredURI[uriSuffixStart:]
	timeSuffix := desiredTime[timeSuffixStart:]

	descendantID := make(ID, 0, len(parentID)+len(uriSuffix)+len(timeSuffix))
	descendantID = append(descendantID, parentID...)
	descendantKey := parentKey

	for _, component := range uriSuffix {
		descendantID = append(descendantID, component)
		descendantKey = GenerateChild(params, descendantKey, descendantID)
	}

	for _, component := range timeSuffix {
		descendantID = append(descendantID, component)
		descendantKey = GenerateChild(params, descendantKey, descendantID)
	}

	return descendantID, descendantKey, nil
}
