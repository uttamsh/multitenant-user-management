package rbac

import (
	"context"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type Service struct {
	repo   Repository
	policy access.Policy
}

func NewService(repo Repository, policy access.Policy) *Service { return &Service{repo, policy} }
func (s *Service) authorize(ctx context.Context, id auth.Identity, action string) (context.Context, error) {
	if err := access.Check(ctx, s.policy, id, action); err != nil {
		return ctx, err
	}
	return access.Bind(ctx, s.policy, action), nil
}
func validRole(req CreateRoleRequest) bool {
	return strings.TrimSpace(req.Name) != "" && utf8.ValidString(req.Name) && utf8.ValidString(req.Description) && utf8.RuneCountInString(req.Name) <= 100 && utf8.RuneCountInString(req.Description) <= 2000 && !strings.ContainsRune(req.Name+req.Description, '\x00')
}
func validVersion(v string) bool { b, err := hex.DecodeString(v); return err == nil && len(b) == 32 }
func (s *Service) CreateRole(ctx context.Context, id auth.Identity, req CreateRoleRequest) (Role, error) {
	ctx, err := s.authorize(ctx, id, "role.create")
	if err != nil {
		return Role{}, err
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !validRole(req) {
		return Role{}, access.ErrInvalid
	}
	return s.repo.CreateRole(ctx, id, req)
}
func (s *Service) ListRoles(ctx context.Context, id auth.Identity, page, size int) (RolePage, error) {
	ctx, err := s.authorize(ctx, id, "role.read")
	if err != nil {
		return RolePage{}, err
	}
	if page < 1 || page > 1000000 || size < 1 || size > 100 {
		return RolePage{}, access.ErrInvalid
	}
	return s.repo.ListRoles(ctx, id, page, size)
}
func (s *Service) GetRole(ctx context.Context, id auth.Identity, roleID string) (Role, error) {
	ctx, err := s.authorize(ctx, id, "role.read")
	if err != nil {
		return Role{}, err
	}
	if !access.UUID(roleID) {
		return Role{}, access.ErrInvalid
	}
	return s.repo.GetRole(ctx, id, roleID)
}
func (s *Service) UpdateRole(ctx context.Context, id auth.Identity, roleID string, req UpdateRoleRequest) (Role, error) {
	ctx, err := s.authorize(ctx, id, "role.update")
	if err != nil {
		return Role{}, err
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !access.UUID(roleID) || !validVersion(req.ExpectedVersion) || !validRole(CreateRoleRequest{Name: req.Name, Description: req.Description}) {
		return Role{}, access.ErrInvalid
	}
	return s.repo.UpdateRole(ctx, id, roleID, req)
}
func (s *Service) DeleteRole(ctx context.Context, id auth.Identity, roleID string, req DeleteRoleRequest) error {
	ctx, err := s.authorize(ctx, id, "role.delete")
	if err != nil {
		return err
	}
	if !access.UUID(roleID) || !validVersion(req.ExpectedVersion) {
		return access.ErrInvalid
	}
	return s.repo.DeleteRole(ctx, id, roleID, req)
}
func (s *Service) Catalog(ctx context.Context, id auth.Identity) ([]Permission, error) {
	ctx, err := s.authorize(ctx, id, "permission.read")
	if err != nil {
		return nil, err
	}
	return s.repo.Catalog(ctx, id)
}
func (s *Service) RolePermissions(ctx context.Context, id auth.Identity, roleID string) ([]Permission, error) {
	ctx, err := s.authorize(ctx, id, "role.read")
	if err != nil {
		return nil, err
	}
	if !access.UUID(roleID) {
		return nil, access.ErrInvalid
	}
	return s.repo.RolePermissions(ctx, id, roleID)
}
func (s *Service) ChangePermission(ctx context.Context, id auth.Identity, roleID string, req PermissionRequest, assign bool) error {
	action := "role_permission.remove"
	if assign {
		action = "role_permission.assign"
	}
	ctx, err := s.authorize(ctx, id, action)
	if err != nil {
		return err
	}
	if !access.UUID(roleID) || !supported(req.Resource, req.Action) {
		return access.ErrInvalid
	}
	return s.repo.ChangePermission(ctx, id, roleID, req, assign)
}
func (s *Service) UserRoles(ctx context.Context, id auth.Identity, userID string) ([]Role, error) {
	ctx, err := s.authorize(ctx, id, "user_permission.read")
	if err != nil {
		return nil, err
	}
	if !access.UUID(userID) {
		return nil, access.ErrInvalid
	}
	return s.repo.UserRoles(ctx, id, userID)
}
func (s *Service) ChangeUserRole(ctx context.Context, id auth.Identity, userID, roleID string, assign bool) error {
	action := "user_role.remove"
	if assign {
		action = "user_role.assign"
	}
	ctx, err := s.authorize(ctx, id, action)
	if err != nil {
		return err
	}
	if !access.UUID(userID) || !access.UUID(roleID) {
		return access.ErrInvalid
	}
	return s.repo.ChangeUserRole(ctx, id, userID, roleID, assign)
}
func (s *Service) Effective(ctx context.Context, id auth.Identity, userID string, self bool) ([]Permission, error) {
	action := "user_permission.read"
	if self {
		action = "identity.active"
		userID = id.UserID
	}
	ctx, err := s.authorize(ctx, id, action)
	if err != nil {
		return nil, err
	}
	if !access.UUID(userID) {
		return nil, access.ErrInvalid
	}
	return s.repo.Effective(ctx, id, userID)
}
