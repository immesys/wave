package poc

import "github.com/immesys/wave/iapi"

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
	Hash             []byte
	State            int
	QueueToken       string
	MaxLabelKeyIndex int
}

type AttestationState struct {
	Hash []byte

	Attestation   *iapi.Attestation
	State         int
	LabelKeyIndex int
}

// type RevocationState struct {
// 	IsEntity   bool
// 	TargetHash []byte
// }

type PLKState struct {
	Slots     [][]byte
	Key       iapi.EntitySecretKeySchemeInstance
	Namespace []byte
}

type ContentKeyState struct {
	Slots [][]byte
	Key   iapi.SlottedSecretKey
}
type PendingLabels struct {
	Slots [][]byte
}
