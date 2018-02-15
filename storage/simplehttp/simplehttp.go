package simplehttp

import "github.com/immesys/wave/iapi"

var _ iapi.StorageDriverInterface = &SimpleHTTPStorage{}

type SimpleHTTPStorage struct {
  url string
}

func (s *SimpleHTTPStorage) Location(context.Context) LocationSchemeInstance

	//This will be called on a specific instantiation of the driver to
	//work out which storage requests to route its way
	Location(context.Context) LocationSchemeInstance

	//Given a set of key/value options from the user's configuration file,
	//create an instance of this storage driver. Initialize will be called
	//on an empty struct instance (e.g (&MyStorage{}).Initialize(cfg))
	Initialize(ctx context.Context, config map[string]string) error

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
