package rbac

import (
	"container/list"
	"strings"
	"sync"
)

// The supported catalog has 20 entries. A fixed-width immutable value bounds
// each entry and avoids sharing mutable permission maps between goroutines.
type permissionSet uint64

func permissionBit(action string) permissionSet {
	for i, p := range Catalog() {
		if i < 64 && p.Resource+"."+p.Action == action {
			return 1 << i
		}
	}
	return 0
}

func permissionsFromActions(actions []string) permissionSet {
	var set permissionSet
	for _, action := range actions {
		set |= permissionBit(action)
	}
	return set
}

type permissionKey struct {
	tenantID, userID string
	revision         int64
}

func cacheKey(tenantID, userID string, revision int64) permissionKey {
	// PostgreSQL UUIDs are case-insensitive; canonicalize equivalent JWT UUIDs.
	return permissionKey{strings.ToLower(tenantID), strings.ToLower(userID), revision}
}

type permissionEntry struct {
	key permissionKey
	set permissionSet
}

// permissionCache is an LRU with a strict entry bound, including obsolete
// revisions and negative (empty-set) results. It has no TTL or revision cache.
type permissionCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[permissionKey]*list.Element
	lru      list.List
}

func newPermissionCache(capacity int) *permissionCache {
	if capacity < 1 {
		capacity = 1
	}
	return &permissionCache{capacity: capacity, entries: make(map[permissionKey]*list.Element)}
}

func (c *permissionCache) get(key permissionKey) (permissionSet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return 0, false
	}
	c.lru.MoveToFront(e)
	return e.Value.(permissionEntry).set, true
}

func (c *permissionCache) put(key permissionKey, set permissionSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		e.Value = permissionEntry{key, set}
		c.lru.MoveToFront(e)
		return
	}
	c.entries[key] = c.lru.PushFront(permissionEntry{key, set})
	if c.lru.Len() > c.capacity {
		old := c.lru.Back()
		delete(c.entries, old.Value.(permissionEntry).key)
		c.lru.Remove(old)
	}
}
