package engine

type engineContextKey string

var PerspectiveKey engineContextKey = "perspective"

//
// things to do:
//
// we don't process the keys from dots that are moving into active
// we need to pull them from the inheritance and process those
// be careful not to deadlock because inserting keys acquires the lock
//
// we need to implement subscriptions for change in perspective and revocation
//
//
// we need to improve the sanitaztion of dots and entities, at least stub it out
//
// we need wavestate (just)
//
// dns server? lol

//top level, when a client connects and gives their perspective entity
//we need to get an engine from cache or create a new engine
//and start it resyncing. Once that is done the client can use the agent
