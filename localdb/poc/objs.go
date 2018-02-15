package poc

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
	//Entity           *iapi.Entity
	EntityDER        []byte
	Hash             []byte
	State            int
	QueueIndex       int
	MaxLabelKeyIndex int
}

type AttestationState struct {
	Hash           []byte
	AttestationDER []byte
	//Attestation   *iapi.Attestation
	State         int
	LabelKeyIndex int
}

// type RevocationState struct {
// 	IsEntity   bool
// 	TargetHash []byte
// }

type PLKState struct {
	Slots [][]byte
	//Key       iapi.EntitySecretKeySchemeInstance
	KeyDER    []byte
	Namespace []byte
}

type ContentKeyState struct {
	Slots  [][]byte
	KeyDER []byte
	//Key   iapi.SlottedSecretKey
}
type PendingLabels struct {
	Slots [][]byte
}
