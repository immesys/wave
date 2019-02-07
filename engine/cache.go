package engine

import (
	"sync"
	"time"

	"github.com/immesys/wave/iapi"
)

var cachemu sync.RWMutex
var entityCache map[ecacheKey]*ecacheItem
var rvkCache map[string]time.Time

var entityCacheTime = 3 * time.Hour

var CacheRevocationChecks = true

type ecacheKey struct {
	Hash     [32]byte
	Location string
}

type ecacheItem struct {
	Val         *iapi.Entity
	CheckExpiry time.Time
}

func init() {
	entityCache = make(map[ecacheKey]*ecacheItem)
	rvkCache = make(map[string]time.Time)
}

func cacheEntity(e *iapi.Entity, loc iapi.LocationSchemeInstance) {
	ar := e.ArrayKeccak256()
	l := loc.(*iapi.LocationSchemeInstanceURL).SerdesForm.Value
	k := ecacheKey{ar, l}
	cachemu.Lock()
	entityCache[k] = &ecacheItem{
		Val:         e,
		CheckExpiry: time.Now().Add(entityCacheTime),
	}
	cachemu.Unlock()
}

func getCachedEntity(h iapi.HashSchemeInstance, loc iapi.LocationSchemeInstance) *iapi.Entity {
	l := loc.(*iapi.LocationSchemeInstanceURL).SerdesForm.Value
	ar := [32]byte{}
	copy(ar[:], h.Value())
	k := ecacheKey{ar, l}
	cachemu.RLock()
	rez, ok := entityCache[k]
	cachemu.RUnlock()
	if ok && rez.CheckExpiry.After(time.Now()) {
		return rez.Val
	}
	return nil
}

func cacheRevocationCheck(id string) {
	if CacheRevocationChecks {
		cachemu.Lock()
		rvkCache[id] = time.Now().Add(1 * time.Hour)
		cachemu.Unlock()
	}
}
func isCachedRevocationCheck(id string) bool {
	cachemu.RLock()
	ts, ok := rvkCache[id]
	cachemu.RUnlock()
	return ok && ts.After(time.Now())
}
