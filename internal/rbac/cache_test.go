package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type sourceState struct {
	revision int64
	set      permissionSet
}
type fakePermissions struct {
	mu                  sync.Mutex
	states              map[string]sourceState
	err, snapshotErr    error
	probes, populations int
	afterProbe          func()
}

func (s *fakePermissions) revision(_ context.Context, id auth.Identity) (int64, error) {
	s.mu.Lock()
	s.probes++
	state, exists := s.states[id.TenantID]
	err, hook := s.err, s.afterProbe
	s.afterProbe = nil
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, auth.ErrForbidden
	}
	return state.revision, nil
}
func (s *fakePermissions) snapshot(_ context.Context, id auth.Identity) (int64, permissionSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.populations++
	if s.snapshotErr != nil {
		return 0, 0, s.snapshotErr
	}
	state, ok := s.states[id.TenantID]
	if !ok {
		return 0, 0, auth.ErrForbidden
	}
	return state.revision, state.set, nil
}

func TestCacheColdWarmNegativeGrantAndTwoInstances(t *testing.T) {
	ctx := context.Background()
	source := &fakePermissions{states: map[string]sourceState{testID.TenantID: {1, 0}}}
	a := &Policy{source, newPermissionCache(4)}
	b := &Policy{source, newPermissionCache(4)}
	for i := 0; i < 2; i++ {
		if err := a.Check(ctx, testID, "user.read"); !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("negative result: %v", err)
		}
	}
	if source.probes != 2 || source.populations != 1 {
		t.Fatal("warm negative entry must still probe DB, but not reload grants")
	}
	source.states[testID.TenantID] = sourceState{2, permissionBit("user.read") | permissionBit("user.update")}
	for _, policy := range []*Policy{a, b} {
		for _, action := range []string{"user.read", "user.update"} {
			if err := policy.Check(ctx, testID, action); err != nil {
				t.Fatal("grant/union not observed", err)
			}
		}
	}
	source.states[testID.TenantID] = sourceState{3, 0}
	for _, policy := range []*Policy{a, b} {
		if err := policy.Check(ctx, testID, "user.read"); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("revocation not observed by independent cache", err)
		}
	}
}

func TestCachePopulationUsesSnapshotRevision(t *testing.T) {
	source := &fakePermissions{states: map[string]sourceState{testID.TenantID: {1, 0}}}
	source.afterProbe = func() { source.states[testID.TenantID] = sourceState{2, permissionBit("user.read")} }
	p := &Policy{source, newPermissionCache(4)}
	if err := p.Check(context.Background(), testID, "user.read"); err != nil {
		t.Fatal(err)
	}
	if _, hit := p.cache.get(cacheKey(testID.TenantID, testID.UserID, 1)); hit {
		t.Fatal("new grants mislabeled with old probe revision")
	}
	if _, hit := p.cache.get(cacheKey(testID.TenantID, testID.UserID, 2)); !hit {
		t.Fatal("coherent snapshot not cached under its own revision")
	}
}

func TestCacheIsolationConcurrentPopulationAndBound(t *testing.T) {
	other := testID
	other.TenantID = "33333333-3333-4333-8333-333333333333"
	source := &fakePermissions{states: map[string]sourceState{
		testID.TenantID: {1, permissionBit("user.read")}, other.TenantID: {1, 0},
	}}
	p := &Policy{source, newPermissionCache(2)}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			if err := p.Check(context.Background(), testID, "user.read"); err != nil {
				t.Error(err)
			}
			if err := p.Check(context.Background(), other, "user.read"); !errors.Is(err, auth.ErrForbidden) {
				t.Error("cross-tenant cache leak", err)
			}
		})
	}
	wg.Wait()
	for i := int64(2); i < 200; i++ {
		p.cache.put(cacheKey(testID.TenantID, testID.UserID, i), 0)
	}
	if len(p.cache.entries) != 2 || p.cache.lru.Len() != 2 {
		t.Fatal("cache is not bounded")
	}
	if _, hit := p.cache.get(cacheKey(testID.TenantID, testID.UserID, 1)); hit {
		t.Fatal("LRU retained evicted revision")
	}
	if _, hit := p.cache.get(cacheKey(testID.TenantID, testID.UserID, 199)); !hit {
		t.Fatal("negative entry was not retained")
	}
}

func TestCacheNeverBypassesLiveIdentityOrDatabaseFailure(t *testing.T) {
	source := &fakePermissions{states: map[string]sourceState{testID.TenantID: {1, permissionBit("user.read")}}}
	p := &Policy{source, newPermissionCache(4)}
	ctx := context.Background()
	if err := p.Check(ctx, testID, "user.read"); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("database unavailable")
	source.err = failure
	if err := p.Check(ctx, testID, "user.read"); !errors.Is(err, failure) {
		t.Fatal("DB failure fell back to cached allow")
	}
	source.err = nil
	delete(source.states, testID.TenantID)
	if err := p.Check(ctx, testID, "user.read"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatal("inactive identity used cached allow")
	}
	source.states[testID.TenantID] = sourceState{2, 0}
	source.snapshotErr = failure
	if err := p.Check(ctx, testID, "user.read"); !errors.Is(err, failure) {
		t.Fatal("population failure used stale permissions")
	}
	if _, hit := p.cache.get(cacheKey(testID.TenantID, testID.UserID, 2)); hit {
		t.Fatal("population error was cached")
	}
	if !errors.Is(identityError(pgx.ErrNoRows), auth.ErrForbidden) {
		t.Fatal("inactive identity changed HTTP semantics")
	}
	if err := p.Check(ctx, auth.Identity{}, "user.read"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("invalid identity accepted")
	}
	if err := p.Check(ctx, testID, "user.*"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatal("unsupported action accepted")
	}
}

func TestPermissionCacheLRUAndCatalogCapacity(t *testing.T) {
	if len(Catalog()) > 64 {
		t.Fatal("permission bitset must be expanded before adding more than 64 catalog entries")
	}
	c := newPermissionCache(2)
	a, b, d := permissionKey{revision: 1}, permissionKey{revision: 2}, permissionKey{revision: 3}
	c.put(a, 0)
	c.put(b, 1)
	c.get(a)
	c.put(d, 2)
	if _, hit := c.get(b); hit {
		t.Fatal("did not evict least-recently-used entry")
	}
	c.put(a, 4)
	if got, hit := c.get(a); !hit || got != 4 || len(c.entries) != 2 {
		t.Fatal("duplicate key insertion broke LRU")
	}
}
