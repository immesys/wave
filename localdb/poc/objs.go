package poc

import (
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
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
	Entity           *entity.Entity
	State            int
	DotIndex         int
	MaxLabelKeyIndex int
}

type DotState struct {
	Dot           *dot.DOT
	State         int
	LabelKeyIndex int
}

type RevocationState struct {
	IsEntity   bool
	TargetHash []byte
}

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
