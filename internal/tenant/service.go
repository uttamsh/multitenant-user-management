package tenant

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type Repository interface {
	Provision(context.Context, CreateRequest) (Tenant, error)
	Get(context.Context, auth.Identity) (Tenant, error)
	Update(context.Context, auth.Identity, UpdateRequest) (Tenant, error)
	SetStatus(context.Context, auth.Identity, StatusRequest) (Tenant, error)
}
type Service struct {
	repo   Repository
	policy access.Policy
}

func NewService(repo Repository, policy access.Policy) *Service {
	return &Service{repo: repo, policy: policy}
}

var codePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

// Provision is for the explicit administrative CLI only; no HTTP route calls it.
func (s *Service) Provision(ctx context.Context, req CreateRequest) (Tenant, error) {
	req, err := NormalizeCreate(req)
	if err != nil {
		return Tenant{}, err
	}
	return s.repo.Provision(ctx, req)
}

func NormalizeCreate(req CreateRequest) (CreateRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Code = strings.TrimSpace(req.Code)
	if !validName(req.Name) || !codePattern.MatchString(req.Code) {
		return CreateRequest{}, access.ErrInvalid
	}
	return req, nil
}
func validName(name string) bool {
	return name != "" && !strings.ContainsRune(name, '\x00') && utf8.ValidString(name) && utf8.RuneCountInString(name) <= 200
}
func (s *Service) Get(ctx context.Context, id auth.Identity) (Tenant, error) {
	if err := access.Check(ctx, s.policy, id, "tenant.read"); err != nil {
		return Tenant{}, err
	}
	ctx = access.Bind(ctx, s.policy, "tenant.read")
	return s.repo.Get(ctx, id)
}
func (s *Service) Update(ctx context.Context, id auth.Identity, req UpdateRequest) (Tenant, error) {
	if err := access.Check(ctx, s.policy, id, "tenant.update"); err != nil {
		return Tenant{}, err
	}
	ctx = access.Bind(ctx, s.policy, "tenant.update")
	req.Name = strings.TrimSpace(req.Name)
	if !validName(req.Name) || req.ExpectedUpdatedAt.IsZero() {
		return Tenant{}, access.ErrInvalid
	}
	return s.repo.Update(ctx, id, req)
}
func (s *Service) SetStatus(ctx context.Context, id auth.Identity, req StatusRequest) (Tenant, error) {
	if err := access.Check(ctx, s.policy, id, "tenant.status"); err != nil {
		return Tenant{}, err
	}
	ctx = access.Bind(ctx, s.policy, "tenant.status")
	if !access.Status(req.Status) || req.ExpectedUpdatedAt.IsZero() {
		return Tenant{}, access.ErrInvalid
	}
	return s.repo.SetStatus(ctx, id, req)
}
