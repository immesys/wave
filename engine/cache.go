package engine

import (
	"sync"
	"time"

	"github.com/immesys/wave/iapi"
)

var cachemu sync.RWMutex
var entityCache map[[32]byte]*ecacheItem
var rvkCache map[string]time.Time

var entityCacheTime = 3 * time.Hour

type ecacheItem struct {
	Val         *iapi.Entity
	CheckExpiry time.Time
}

func init() {
	entityCache = make(map[[32]byte]*ecacheItem)
	rvkCache = make(map[string]time.Time)
}

func cacheEntity(e *iapi.Entity) {
	k := e.ArrayKeccak256()
	cachemu.Lock()
	entityCache[k] = &ecacheItem{
		Val:         e,
		CheckExpiry: time.Now().Add(entityCacheTime),
	}
	cachemu.Unlock()
}

func getCachedEntity(h iapi.HashSchemeInstance) *iapi.Entity {
	ak := [32]byte{}
	copy(ak[:], h.Value())
	cachemu.RLock()
	rez, ok := entityCache[ak]
	cachemu.RUnlock()
	if ok && rez.CheckExpiry.After(time.Now()) {
		return rez.Val
	}
	return nil
}

func cacheRevocationCheck(id string) {
	cachemu.Lock()
	rvkCache[id] = time.Now().Add(1 * time.Hour)
	cachemu.Unlock()
}
func isCachedRevocationCheck(id string) bool {
	cachemu.RLock()
	ts, ok := rvkCache[id]
	cachemu.RUnlock()
	return ok && ts.After(time.Now())
}
