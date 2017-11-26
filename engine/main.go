package engine

type engineContextKey string

var perspectiveKey engineContextKey = "perspective"


things to do:

we don't process the keys from dots that are moving into active
we need to pull them from the inheritance and process those
be careful not to deadlock because inserting keys acquires the lock

we need to implement subscriptions for change in perspective and revocation

we need to do lookup dot in perspective (easy?)

we need to wait for sync to finish on startup, implement that function

we need to improve the sanitaztion of dots and entities, at least stub it out

we need wavestate (just)
