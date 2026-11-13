package tenant

import (
	"context"
	"errors"
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
	request CreateRequest
}

func (r *fakeRepository) Provision(_ context.Context, req CreateRequest) (Tenant, error) {
	r.request = req
	return Tenant{ID: actor.TenantID, Name: req.Name, Code: req.Code}, nil
}
func TestProvisionValidation(t *testing.T) {
	r := &fakeRepository{}
	s := NewService(r, access.DenyAll{})
	v, err := s.Provision(context.Background(), CreateRequest{Name: " Acme ", Code: " acme "})
	if err != nil || v.Name != "Acme" || v.Code != "acme" {
		t.Fatal("provision normalization failed")
	}
	for _, req := range []CreateRequest{{Name: "", Code: "ok"}, {Name: "Test", Code: "BAD CODE"}, {Name: "Test", Code: ""}} {
		if _, err := s.Provision(context.Background(), req); !errors.Is(err, access.ErrInvalid) {
			t.Fatal("invalid provisioning accepted")
		}
	}
}
func TestTenantServiceFailsClosed(t *testing.T) {
	for _, policy := range []access.Policy{nil, access.DenyAll{}} {
		s := NewService(nil, policy)
		if _, err := s.Get(context.Background(), actor); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("read bypassed policy")
		}
		if _, err := s.Update(context.Background(), actor, UpdateRequest{Name: "Name", ExpectedUpdatedAt: time.Now()}); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("update bypassed policy")
		}
		if _, err := s.SetStatus(context.Background(), actor, StatusRequest{Status: "suspended", ExpectedUpdatedAt: time.Now()}); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("status bypassed policy")
		}
	}
	s := NewService(nil, allowPolicy{})
	if _, err := s.Get(context.Background(), auth.Identity{}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("missing identity accepted")
	}
	if _, err := s.Update(context.Background(), actor, UpdateRequest{Name: ""}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid update accepted")
	}
	if _, err := s.SetStatus(context.Background(), actor, StatusRequest{Status: "unknown", ExpectedUpdatedAt: time.Now()}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid status accepted")
	}
}
