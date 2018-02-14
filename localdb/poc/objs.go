// +build ignore

package poc

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/iapi"
)

//go:generate msgp -io=false -tests=false

const (
	_ = iota
	StateInteresting
	StateExpired
	StateRevoked
	StateMalformed //treat like revoked
	StateEntRevoked
	StatePending
	StateLabelled
	StateActive
)

type EntityState struct {
	Entity           *iapi.Entity
	State            int
	DotIndex         int
	MaxLabelKeyIndex int
}

type AttestationState struct {
	Dot           *iapi.Attestation
	State         int
	LabelKeyIndex int
}

// type RevocationState struct {
// 	IsEntity   bool
// 	TargetHash []byte
// }

type PLKState struct {
	Slots     [][]byte
	Key       *oaque.PrivateKey
	Namespace []byte
}

type ContentKeyState struct {
	Slots [][]byte
	Key   *oaque.PrivateKey
}
type PendingLabels struct {
	Slots [][]byte
}
