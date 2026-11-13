package user

import (
	"context"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

type Repository interface {
	Create(context.Context, auth.Identity, CreateRequest, string) (User, error)
	List(context.Context, auth.Identity, ListQuery) (Page, error)
	Get(context.Context, auth.Identity, string) (User, error)
	Update(context.Context, auth.Identity, string, UpdateRequest, *string) (User, error)
	SoftDelete(context.Context, auth.Identity, string, VersionRequest) error
	AddMembership(context.Context, auth.Identity, MembershipRequest) (Membership, error)
	SetMembershipStatus(context.Context, auth.Identity, string, MembershipStatusRequest) (Membership, error)
	RemoveMembership(context.Context, auth.Identity, string, VersionRequest) error
}
type Service struct {
	repo   Repository
	policy access.Policy
}

func NewService(repo Repository, policy access.Policy) *Service { return &Service{repo, policy} }
func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email && utf8.ValidString(email) && utf8.RuneCountInString(email) <= 255
}
func validName(name string) bool {
	return name != "" && !strings.ContainsRune(name, '\x00') && utf8.ValidString(name) && utf8.RuneCountInString(name) <= 200
}
func validPassword(password string) bool { return len(password) >= 12 && len(password) <= 72 }
func (s *Service) Create(ctx context.Context, id auth.Identity, req CreateRequest) (User, error) {
	if err := access.Check(ctx, s.policy, id, "user.create"); err != nil {
		return User{}, err
	}
	ctx = access.Bind(ctx, s.policy, "user.create")
	req.Email = strings.TrimSpace(req.Email)
	req.FullName = strings.TrimSpace(req.FullName)
	if !validEmail(req.Email) || !validName(req.FullName) || !validPassword(req.Password) {
		return User{}, access.ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	req.Password = "" // Clear plaintext before crossing into the repository layer.
	return s.repo.Create(ctx, id, req, string(hash))
}
func (s *Service) List(ctx context.Context, id auth.Identity, q ListQuery) (Page, error) {
	if err := access.Check(ctx, s.policy, id, "user.read"); err != nil {
		return Page{}, err
	}
	ctx = access.Bind(ctx, s.policy, "user.read")
	q.Search = strings.TrimSpace(q.Search)
	if q.Page < 1 || q.Page > 1000000 || q.PageSize < 1 || q.PageSize > 100 || utf8.RuneCountInString(q.Search) > 200 || (q.MembershipStatus != "" && !access.Status(q.MembershipStatus)) {
		return Page{}, access.ErrInvalid
	}
	return s.repo.List(ctx, id, q)
}
func (s *Service) Get(ctx context.Context, id auth.Identity, userID string) (User, error) {
	if err := access.Check(ctx, s.policy, id, "user.read"); err != nil {
		return User{}, err
	}
	ctx = access.Bind(ctx, s.policy, "user.read")
	if !access.UUID(userID) {
		return User{}, access.ErrInvalid
	}
	return s.repo.Get(ctx, id, userID)
}
func (s *Service) Update(ctx context.Context, id auth.Identity, userID string, req UpdateRequest) (User, error) {
	if err := access.Check(ctx, s.policy, id, "user.update"); err != nil {
		return User{}, err
	}
	ctx = access.Bind(ctx, s.policy, "user.update")
	if !access.UUID(userID) || req.ExpectedUpdatedAt.IsZero() || (req.Email == nil && req.FullName == nil && req.Password == nil) {
		return User{}, access.ErrInvalid
	}
	if req.Email != nil {
		v := strings.TrimSpace(*req.Email)
		if !validEmail(v) {
			return User{}, access.ErrInvalid
		}
		req.Email = &v
	}
	if req.FullName != nil {
		v := strings.TrimSpace(*req.FullName)
		if !validName(v) {
			return User{}, access.ErrInvalid
		}
		req.FullName = &v
	}
	var hash *string
	if req.Password != nil {
		if !validPassword(*req.Password) {
			return User{}, access.ErrInvalid
		}
		bytes, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			return User{}, err
		}
		v := string(bytes)
		hash = &v
		req.Password = nil
	}
	return s.repo.Update(ctx, id, userID, req, hash)
}
func (s *Service) SoftDelete(ctx context.Context, id auth.Identity, userID string, req VersionRequest) error {
	if err := access.Check(ctx, s.policy, id, "user.delete"); err != nil {
		return err
	}
	ctx = access.Bind(ctx, s.policy, "user.delete")
	if !access.UUID(userID) || req.ExpectedUpdatedAt.IsZero() {
		return access.ErrInvalid
	}
	return s.repo.SoftDelete(ctx, id, userID, req)
}
func (s *Service) AddMembership(ctx context.Context, id auth.Identity, req MembershipRequest) (Membership, error) {
	if err := access.Check(ctx, s.policy, id, "membership.create"); err != nil {
		return Membership{}, err
	}
	ctx = access.Bind(ctx, s.policy, "membership.create")
	if !access.UUID(req.UserID) {
		return Membership{}, access.ErrInvalid
	}
	return s.repo.AddMembership(ctx, id, req)
}
func (s *Service) SetMembershipStatus(ctx context.Context, id auth.Identity, userID string, req MembershipStatusRequest) (Membership, error) {
	if err := access.Check(ctx, s.policy, id, "membership.update"); err != nil {
		return Membership{}, err
	}
	ctx = access.Bind(ctx, s.policy, "membership.update")
	if !access.UUID(userID) || !access.Status(req.Status) || req.ExpectedUpdatedAt.IsZero() {
		return Membership{}, access.ErrInvalid
	}
	return s.repo.SetMembershipStatus(ctx, id, userID, req)
}
func (s *Service) RemoveMembership(ctx context.Context, id auth.Identity, userID string, req VersionRequest) error {
	if err := access.Check(ctx, s.policy, id, "membership.delete"); err != nil {
		return err
	}
	ctx = access.Bind(ctx, s.policy, "membership.delete")
	if !access.UUID(userID) || req.ExpectedUpdatedAt.IsZero() {
		return access.ErrInvalid
	}
	return s.repo.RemoveMembership(ctx, id, userID, req)
}
