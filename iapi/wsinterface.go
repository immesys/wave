package iapi

import (
	"context"
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
	//Removes key, no error if it does not exist
	Remove(ctx context.Context, key string) (err error)
}

type PendingAttestation struct {
	Err         error
	Attestation *Attestation
	Keccak256   []byte
	//Only for pending without partition
	LabelKeyIndex *int
}

type PendingNameDeclaration struct {
	Err             error
	NameDeclaration *NameDeclaration
	Keccak256       []byte
	LabelKeyIndex   *int
}

type InterestingEntityResult struct {
	Entity *Entity
	Err    error
}

// type ReverseLookupResult struct {
// 	HashSchemeInstance   []byte
// 	IsDOT  bool
// 	Attestatopm    *dot.DOT
// 	Entity *entity.Entity
// 	Err    error
// }

type LookupFromResult struct {
	Attestation *Attestation
	Err         error
}

type ResolveResult struct {
	NameDeclaration *NameDeclaration
	Err             error
}

type LookupFromFilter struct {
	Valid     *bool
	Namespace []byte
	GlobalNS  *bool
}

type LocationResult struct {
	Location LocationSchemeInstance
	Err      error
}

type State struct {
	ValidActive bool
	Expired     bool
	Revoked     bool
	EntRevoked  bool
}

type WaveState interface {

	//Perspective functions

	//Set the last checked time for the given revocation option id
	AddRevocationCheck(ctx context.Context, id string, ts int64) error
	//Get the last checked time for the given revocation id, if available
	GetRevocationCheck(ctx context.Context, id string) (*int64, error)

	//This is idempotent, an entity in any state other than unknown will
	//be ignored by this function
	MoveEntityInterestingP(ctx context.Context, ent *Entity, loc LocationSchemeInstance) error
	//This does not return revoked or expired entities, even though the
	//function above considers them "interesting"
	GetInterestingEntitiesP(ctx context.Context) chan InterestingEntityResult
	IsEntityInterestingP(ctx context.Context, hash HashSchemeInstance) (bool, error)

	//TODO ensure channel stops if context is cancelled
	LocationsForEntity(ctx context.Context, ent *Entity) ([]LocationSchemeInstance, error)
	//The backing data gets populated by the MoveX objects, so this is
	//can give false negatives. The channel must be consumed completely
	//or the context cancelled
	//GetInterestingByRevocationHashSchemeInstanceP(ctx context.Context, rvkHashSchemeInstance []byte) chan ReverseLookupResult

	//This is a key that decrypts the partition label (WR1 uses IBE)
	GetPartitionLabelKeyP(ctx context.Context, subject HashSchemeInstance, index int) (EntitySecretKeySchemeInstance, error)
	InsertPartitionLabelKeyP(ctx context.Context, attester HashSchemeInstance, key EntitySecretKeySchemeInstance) (new bool, err error)

	//Return true from callback to continue iterating
	WR1KeysForP(ctx context.Context, subject HashSchemeInstance, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	//TODO this must be idempotenty, like don't add in a secret if we have a more
	//powerful one already
	InsertWR1KeysForP(ctx context.Context, attester HashSchemeInstance, k SlottedSecretKey) error

	MoveAttestationPendingP(ctx context.Context, at *Attestation, labelKeyIndex int) error
	//Assume dot already inserted into pending, but update the labelKeyIndex
	UpdateAttestationPendingP(ctx context.Context, at *Attestation, labelKeyIndex int) error
	MoveAttestationLabelledP(ctx context.Context, at *Attestation) error
	MoveAttestationActiveP(ctx context.Context, at *Attestation) error
	MoveAttestationExpiredP(ctx context.Context, at *Attestation) error
	MoveAttestationEntRevokedP(ctx context.Context, at *Attestation) error
	MoveAttestationMalformedP(ctx context.Context, HashSchemeInstance HashSchemeInstance) error
	GetLabelledAttestationsP(ctx context.Context, subject HashSchemeInstance, partition [][]byte) chan PendingAttestation
	//If possible, only return pending dots with a secret index less than siLT
	GetPendingAttestationsP(ctx context.Context, subject HashSchemeInstance, lkiLT int) chan PendingAttestation

	//Like attestations, but for namedecl
	MoveNameDeclarationPendingP(ctx context.Context, nd *NameDeclaration, labelKeyIndex int) error
	//Assume dot already inserted into pending, but update the labelKeyIndex
	UpdateNameDeclarationPendingP(ctx context.Context, nd *NameDeclaration, labelKeyIndex int) error
	MoveNameDeclarationLabelledP(ctx context.Context, nd *NameDeclaration) error
	MoveNameDeclarationActiveP(ctx context.Context, nd *NameDeclaration) error
	MoveNameDeclarationExpiredP(ctx context.Context, nd *NameDeclaration) error
	MoveNameDeclarationMalformedP(ctx context.Context, HashSchemeInstance HashSchemeInstance) error
	GetLabelledNameDeclarationsP(ctx context.Context, namespace HashSchemeInstance, partition [][]byte) chan PendingNameDeclaration
	//If possible, only return pending dots with a secret index less than siLT
	GetPendingNameDeclarationP(ctx context.Context, namespace HashSchemeInstance, lkiLT int) chan PendingNameDeclaration
	MoveNameDeclarationRevokedP(ctx context.Context, nd *NameDeclaration) error

	//Interact with active namedecls
	//Results should be sorted with the latest start date appearing first
	ResolveNameDeclarationsP(ctx context.Context, attester HashSchemeInstance, name string) chan ResolveResult
	ResolveReverseName(ctx context.Context, hi HashSchemeInstance) (name string, err error)
	InsertReverseName(ctx context.Context, name string, hi HashSchemeInstance) (err error)
	GetNameDeclarationP(ctx context.Context, hi HashSchemeInstance) (nd *NameDeclaration, err error)

	GetEntityPartitionLabelKeyIndexP(ctx context.Context, entHashSchemeInstance HashSchemeInstance) (bool, int, error)
	GetAttestationP(ctx context.Context, HashSchemeInstance HashSchemeInstance) (at *Attestation, err error)
	GetActiveAttestationsFromP(ctx context.Context, attester HashSchemeInstance, filter *LookupFromFilter) chan LookupFromResult
	GetActiveAttestationsToP(ctx context.Context, subject HashSchemeInstance, filter *LookupFromFilter) chan LookupFromResult
	GetEntityQueueTokenP(ctx context.Context, loc LocationSchemeInstance, hsh HashSchemeInstance) (okay bool, token string, err error)
	SetEntityQueueTokenP(ctx context.Context, loc LocationSchemeInstance, hsh HashSchemeInstance, token string) error

	//Global (non perspective) functions
	MoveEntityRevokedG(ctx context.Context, ent *Entity) error
	MoveEntityExpiredG(ctx context.Context, ent *Entity) error
	MoveAttestationRevokedG(ctx context.Context, at *Attestation) error

	//This only returns entities we happen to have because they were interesting
	//to someone, so the caller must handle a nil,nil result and go hit the chain
	GetEntityByHashSchemeInstanceG(ctx context.Context, hsh HashSchemeInstance) (*Entity, error)
}

//TODO
// wave state is global, the P methods expect a perspective key in the context
// wave state should not cache anything that requires external cache invalidation
// wave state will not go to the chain storage if it misses, the caller must
// handle that and pass the result back down
