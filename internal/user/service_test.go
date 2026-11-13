package user

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type allowPolicy struct{}

func (allowPolicy) Check(context.Context, auth.Identity, string) error { return nil }

var actor = auth.Identity{UserID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222"}

type fakeRepository struct {
	Repository
	request  CreateRequest
	hash     string
	identity auth.Identity
}

func (r *fakeRepository) Create(_ context.Context, id auth.Identity, req CreateRequest, hash string) (User, error) {
	r.request = req
	r.hash = hash
	r.identity = id
	return User{ID: actor.UserID, Email: req.Email, FullName: req.FullName}, nil
}
func TestUserPasswordBoundary(t *testing.T) {
	r := &fakeRepository{}
	s := NewService(r, allowPolicy{})
	v, err := s.Create(context.Background(), actor, CreateRequest{Email: " User@Example.test ", FullName: " Test User ", Password: "development-only-password"})
	if err != nil || r.request.Password != "" || !auth.VerifyPassword(r.hash, "development-only-password") || r.identity != actor || v.FullName != "Test User" || r.request.Email != "User@Example.test" {
		t.Fatal("password hashing, normalization, or scope failed")
	}
	bytes, _ := json.Marshal(v)
	if strings.Contains(string(bytes), "password") || strings.Contains(string(bytes), r.hash) {
		t.Fatal("response exposed password material")
	}
	for _, password := range []string{"short", strings.Repeat("a", 73)} {
		if _, err := s.Create(context.Background(), actor, CreateRequest{Email: "a@example.test", FullName: "A", Password: password}); !errors.Is(err, access.ErrInvalid) {
			t.Fatal("invalid password accepted")
		}
	}
}
func TestUserServiceFailsClosed(t *testing.T) {
	s := NewService(nil, access.DenyAll{})
	ctx := context.Background()
	now := time.Now()
	checks := []func() error{
		func() error { _, err := s.Create(ctx, actor, CreateRequest{}); return err },
		func() error { _, err := s.List(ctx, actor, ListQuery{}); return err },
		func() error { _, err := s.Get(ctx, actor, actor.UserID); return err },
		func() error { _, err := s.Update(ctx, actor, actor.UserID, UpdateRequest{}); return err },
		func() error { return s.SoftDelete(ctx, actor, actor.UserID, VersionRequest{now}) },
		func() error { _, err := s.AddMembership(ctx, actor, MembershipRequest{actor.UserID}); return err },
		func() error {
			_, err := s.SetMembershipStatus(ctx, actor, actor.UserID, MembershipStatusRequest{})
			return err
		},
		func() error { return s.RemoveMembership(ctx, actor, actor.UserID, VersionRequest{now}) },
	}
	for _, check := range checks {
		if err := check(); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("operation bypassed deny-all policy")
		}
	}
}
func TestUserInputValidation(t *testing.T) {
	s := NewService(nil, allowPolicy{})
	ctx := context.Background()
	if _, err := s.Get(ctx, actor, "invalid"); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid UUID accepted")
	}
	for _, q := range []ListQuery{{0, 20, "", ""}, {1, 101, "", ""}, {1, 20, "", "removed"}, {1000001, 20, "", ""}} {
		if _, err := s.List(ctx, actor, q); !errors.Is(err, access.ErrInvalid) {
			t.Fatal("invalid pagination or filter accepted")
		}
	}
	if _, err := s.Update(ctx, actor, actor.UserID, UpdateRequest{ExpectedUpdatedAt: time.Now()}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("empty update accepted")
	}
	if _, err := s.AddMembership(ctx, actor, MembershipRequest{UserID: "bad"}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid membership target accepted")
	}
	if _, err := s.SetMembershipStatus(ctx, actor, actor.UserID, MembershipStatusRequest{Status: "removed", ExpectedUpdatedAt: time.Now()}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid membership status accepted")
	}
}
