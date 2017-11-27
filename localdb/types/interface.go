package types

import (
	"context"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/immesys/wave/dot"
	"github.com/immesys/wave/entity"
)

type KeyValue struct {
	Key   string
	Value []byte
}
type LowLevelStorage interface {
	//If the key does not exist, return nil value and nil err
	Load(ctx context.Context, key string) (val []byte, err error)
	//For both of these functions, you either have to fully consume the value channel,
	//or cancel the context.
	LoadPrefix(ctx context.Context, key string) (results chan KeyValue, err chan error)
	//Values will be nil
	LoadPrefixKeys(ctx context.Context, key string) (results chan KeyValue, err chan error)
	Store(ctx context.Context, key string, val []byte) (err error)
}

type PendingDOTResult struct {
	Err  error
	Dot  *dot.DOT
	Hash []byte
	//Only for pending without partition
	LabelKeyIndex *int
}

type Secret struct {
	//If true, this is a main content key,
	//If false this is a label key
	IsContentKey bool
	Slots        [][]byte
	Key          *oaque.PrivateKey
}

//Permits equality comparisons
//TODO we should move this out of here lol
func (s *Secret) Hash() [32]byte {
	panic("ni")
}

type InterestingEntityResult struct {
	Hash []byte
	Err  error
}

type ReverseLookupResult struct {
	Hash   []byte
	IsDOT  bool
	Dot    *dot.DOT
	Entity *entity.Entity
	Err    error
}

type LookupFromResult struct {
	Dot *dot.DOT
	Err error
}

type LookupFromFilter struct {
	Valid     *bool
	Namespace []byte
	GlobalNS  *bool
}

type State struct {
	ValidActive bool
	Expired     bool
	Revoked     bool
	EntRevoked  bool
}

type WaveState interface {

	//Perspective functions

	//This is idempotent, an entity in any state other than unknown will
	//be ignored by this function
	MoveEntityInterestingP(ctx context.Context, ent *entity.Entity) error
	//This does not return revoked or expired entities, even though the
	//function above considers them "interesting"
	GetInterestingEntitiesP(ctx context.Context) chan InterestingEntityResult
	IsEntityInterestingP(ctx context.Context, hash []byte) (bool, error)

	//The backing data gets populated by the MoveX objects, so this is
	//can give false negatives. The channel must be consumed completely
	//or the context cancelled
	GetInterestingByRevocationHashP(ctx context.Context, rvkhash []byte) chan ReverseLookupResult

	GetPartitionLabelKeyP(ctx context.Context, dst []byte, index int) (*Secret, error)
	InsertPartitionLabelKeyP(ctx context.Context, from []byte, namespace []byte, key *oaque.PrivateKey) (new bool, err error)

	OAQUEKeysForP(ctx context.Context, dst []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error
	//TODO this must be idempotenty, like don't add in a secret if we have a more
	//powerful one already
	InsertOAQUEKeysForP(ctx context.Context, from []byte, slots [][]byte, k *oaque.PrivateKey) error

	MoveDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error
	//Assume dot already inserted into pending, but update the labelKeyIndex
	UpdateDotPendingP(ctx context.Context, dt *dot.DOT, labelKeyIndex int) error
	MoveDotLabelledP(ctx context.Context, dt *dot.DOT) error
	MoveDotActiveP(ctx context.Context, dt *dot.DOT) error
	MoveDotExpiredP(ctx context.Context, dt *dot.DOT) error
	MoveDotEntRevokedP(ctx context.Context, dt *dot.DOT) error
	MoveDotMalformedP(ctx context.Context, hash []byte) error
	GetLabelledDotsP(ctx context.Context, dst []byte, partition [][]byte) chan PendingDOTResult
	//If possible, only return pending dots with a secret index less than siLT
	GetPendingDotsP(ctx context.Context, dst []byte, lkiLT int) chan PendingDOTResult
	GetEntityPartitionLabelKeyIndexP(ctx context.Context, enthash []byte) (bool, int, error)
	GetDotP(ctx context.Context, hash []byte) (d *dot.DOT, err error)
	GetActiveDotsFromP(ctx context.Context, src []byte, filter *LookupFromFilter) chan LookupFromResult
	GetEntityDotIndexP(ctx context.Context, hsh []byte) (okay bool, dotIndex int, err error)
	SetEntityDotIndexP(ctx context.Context, hsh []byte, dotIndex int) error

	//Global (non perspective) functions
	MoveEntityRevokedG(ctx context.Context, ent *entity.Entity) error
	MoveEntityExpiredG(ctx context.Context, ent *entity.Entity) error
	MoveDotRevokedG(ctx context.Context, dot *dot.DOT) error

	//This only returns entities we happen to have because they were interesting
	//to someone, so the caller must handle a nil,nil result and go hit the chain
	GetEntityByHashG(ctx context.Context, hsh []byte) (*entity.Entity, error)
}

//TODO
// wave state is global, the P methods expect a perspective key in the context
// wave state should not cache anything that requires external cache invalidation
// wave state will not go to the chain storage if it misses, the caller must
// handle that and pass the result back down
