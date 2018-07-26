package iapi

import (
	"context"
	"errors"
)

type StorageDriverCharacteristics struct {
	//In WAVE a perspective is a particular view of the global graph that
	//is defined by a perspective entity. If the storage provider requires
	//a distinct instantiation per perspective, set this to true. Regardless
	//of this setting, the perspective entity is available via
	//  ctx.Value(consts.PerspectiveKey).(*iapi.EntitySecrets)
	// default is False
	PerspectiveDependant *bool

	// When generating the default config file for the user,
	// what are the default config options
	DefaultConfiguration map[string]string

	// If there is no specific hash scheme (the provider is agnostic)
	// then leave this nil
	PreferredHashScheme HashScheme
}

//Should be returned by Get if the object is not found
var ErrObjectNotFound = errors.New("object not found")

//Should be returned by Put if if fails to store the object
var ErrObjectNotPut = errors.New("failed to put object")

//Should be returned byy any of the four main functions if it receives an invalid request
// e.g., empty object passed to a PUT function
var ErrInvalidRequest = errors.New("invalid request")

//Should be returned by any of the four main functions if not implemented
var ErrNotImplemented = errors.New("not implemented")

//Should be returned by IterateQueue if there are no more entries
var ErrNoMore = errors.New("no more")

type StorageDriverInterface interface {

	// //This will be called on nil, the storage should return its static
	// //characteristics which will be used by the aggregate storage driver
	// //layer to work out how to interface with this provider
	// Characteristics() *StorageDriverCharacteristics

	//This will be called on a specific instantiation of the driver to
	//work out which storage requests to route its way
	Location(context.Context) LocationSchemeInstance

	//When constructing an attestation with a particular location in mind,
	//the entity hashes used within the attestation should match the scheme of
	//the storage. This method enables the engine to know the hash in advance
	PreferredHashScheme() HashScheme

	//Given a set of key/value options from the user's configuration file,
	//create an instance of this storage driver. Initialize will be called
	//on an empty struct instance (e.g (&MyStorage{}).Initialize(cfg))
	Initialize(ctx context.Context, name string, config map[string]string) error

	//Retrieve the status of this storage driver (ready for use etc)
	//You should only return an error on context timeout, any other
	//error is probably indicative of an non-operational status and should be
	//returned as such
	Status(ctx context.Context) (operational bool, info map[string]string, err error)

	//Put the given object into storage. This does not queue any notifications
	//It should return the Hash of the object using the providers preferred
	//hash scheme. It should only return when the object
	Put(ctx context.Context, content []byte) (HashSchemeInstance, error)

	//Get the given object from storage. A nonexistant object should return
	//ErrObjectNotFound.
	Get(ctx context.Context, hash HashSchemeInstance) (content []byte, err error)

	//Place the given object into the given queue.
	Enqueue(ctx context.Context, queueId HashSchemeInstance, object HashSchemeInstance) error

	//Iterate over the given queue. Returns nil, "", ErrNoMore if there are no more
	//entries. Must accept "" as iteratorToken to mean the first entry
	IterateQueue(ctx context.Context, queueId HashSchemeInstance, iteratorToken string) (object HashSchemeInstance, nextToken string, err error)
}

type StorageDriverStatus struct {
	Operational bool
	Info        map[string]string
}
type GetResult struct {
	Attestation     *Attestation
	NameDeclaration *NameDeclaration
}
type StorageInterface interface {
	PutBlob(ctx context.Context, loc LocationSchemeInstance, content []byte) (HashSchemeInstance, error)
	GetBlob(ctx context.Context, loc LocationSchemeInstance, hash HashSchemeInstance) ([]byte, error)
	GetEntity(ctx context.Context, loc LocationSchemeInstance, hash HashSchemeInstance) (*Entity, error)
	PutEntity(ctx context.Context, loc LocationSchemeInstance, ent *Entity) (HashSchemeInstance, error)
	GetAttestation(ctx context.Context, loc LocationSchemeInstance, hash HashSchemeInstance) (*Attestation, error)
	GetAttestationOrDeclaration(ctx context.Context, loc LocationSchemeInstance, hash HashSchemeInstance) (*GetResult, error)
	PutNameDeclaration(ctx context.Context, loc LocationSchemeInstance, nd *NameDeclaration) (HashSchemeInstance, error)
	PutAttestation(ctx context.Context, loc LocationSchemeInstance, att *Attestation) (HashSchemeInstance, error)
	IterateQeueue(ctx context.Context, loc LocationSchemeInstance, queueId HashSchemeInstance, token string) (object HashSchemeInstance, nextToken string, err error)
	Enqueue(ctx context.Context, loc LocationSchemeInstance, queueId HashSchemeInstance, object HashSchemeInstance) error
	HashSchemeFor(loc LocationSchemeInstance) (HashScheme, error)
	Status(ctx context.Context) (map[string]StorageDriverStatus, error)
	RegisteredLocations(ctx context.Context) (map[string]LocationSchemeInstance, error)
	DefaultLocation(ctx context.Context) LocationSchemeInstance
	LocationByName(ctx context.Context, name string) (LocationSchemeInstance, error)
}

var injectedStorageInterface StorageInterface

func InjectStorageInterface(si StorageInterface) {
	if injectedStorageInterface != nil {
		panic("injected SI more than once")
	}
	injectedStorageInterface = si
}
func SI() StorageInterface {
	if injectedStorageInterface == nil {
		panic("did not inject SI")
	}
	return injectedStorageInterface
}
