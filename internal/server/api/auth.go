package api

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/server/auth"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
)

type principalKey struct{}

// PrincipalFrom returns the authenticated operator of a request.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

func peerIP(addr string) *netip.Addr {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil
	}
	a := ap.Addr().Unmap()
	return &a
}

// StepUpHeader is set on errors that a fresh TOTP code (AuthService.StepUp) would fix.
const StepUpHeader = "Sm-Step-Up"

// NewAuthInterceptor requires a valid session on every call except the ones in public.
func NewAuthInterceptor(svc *auth.Service, public ...string) connect.UnaryInterceptorFunc {
	open := map[string]bool{}
	for _, p := range public {
		open[p] = true
	}
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if open[req.Spec().Procedure] {
				return next(ctx, req)
			}
			token, ok := strings.CutPrefix(req.Header().Get("Authorization"), "Bearer ")
			if !ok {
				return nil, connect.NewError(connect.CodeUnauthenticated, auth.ErrUnauthenticated)
			}
			p, err := svc.Authenticate(ctx, strings.TrimSpace(token), peerIP(req.Peer().Addr))
			if err != nil {
				if errors.Is(err, auth.ErrUnauthenticated) {
					return nil, connect.NewError(connect.CodeUnauthenticated, err)
				}
				return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
			}
			return next(context.WithValue(ctx, principalKey{}, p), req)
		}
	}
}

// mapAuthErr converts authorization errors to connect errors.
func mapAuthErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrStepUpRequired):
		ce := connect.NewError(connect.CodePermissionDenied, err)
		ce.Meta().Set(StepUpHeader, "required")
		return ce
	case errors.Is(err, auth.ErrForbidden):
		return connect.NewError(connect.CodePermissionDenied, err)
	default:
		return err
	}
}

// AuthServer implements operatorv1connect.AuthServiceHandler.
type AuthServer struct {
	operatorv1connect.UnimplementedAuthServiceHandler
	Auth  *auth.Service
	Store *store.Store
}

// Login implements AuthService.Login.
func (s *AuthServer) Login(ctx context.Context, req *connect.Request[operatorv1.LoginRequest]) (*connect.Response[operatorv1.LoginResponse], error) {
	tok, p, err := s.Auth.Login(ctx, req.Msg.GetEmail(), req.Msg.GetPassword(), req.Msg.GetTotpCode(), peerIP(req.Peer().Addr), req.Header().Get("User-Agent"))
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, auth.ErrInvalidCredentials):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	return connect.NewResponse(&operatorv1.LoginResponse{
		Token: tok, Email: p.Email, ExpiresAt: timestamppb.New(time.Now().Add(auth.SessionLifetime)),
	}), nil
}

// Logout implements AuthService.Logout.
func (s *AuthServer) Logout(ctx context.Context, _ *connect.Request[operatorv1.LogoutRequest]) (*connect.Response[operatorv1.LogoutResponse], error) {
	p, _ := PrincipalFrom(ctx)
	if err := s.Auth.Logout(ctx, p); err != nil {
		return nil, err
	}
	return connect.NewResponse(&operatorv1.LogoutResponse{}), nil
}

// WhoAmI implements AuthService.WhoAmI.
func (s *AuthServer) WhoAmI(ctx context.Context, _ *connect.Request[operatorv1.WhoAmIRequest]) (*connect.Response[operatorv1.WhoAmIResponse], error) {
	p, _ := PrincipalFrom(ctx)
	rows, err := s.Store.ListRoleBindings(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	resp := &operatorv1.WhoAmIResponse{UserId: p.UserID.String(), Email: p.Email, MfaAt: timestamppb.New(p.MFAAt)}
	for _, r := range rows {
		g := ""
		if r.GroupName != nil {
			g = *r.GroupName
		}
		resp.Roles = append(resp.Roles, &operatorv1.RoleGrant{Group: g, Role: r.Role})
	}
	return connect.NewResponse(resp), nil
}

// StepUp implements AuthService.StepUp.
func (s *AuthServer) StepUp(ctx context.Context, req *connect.Request[operatorv1.StepUpRequest]) (*connect.Response[operatorv1.StepUpResponse], error) {
	p, _ := PrincipalFrom(ctx)
	if err := s.Auth.StepUp(ctx, p, req.Msg.GetTotpCode()); err != nil {
		if errors.Is(err, auth.ErrBadCode) {
			return nil, connect.NewError(connect.CodePermissionDenied, err)
		}
		return nil, err
	}
	return connect.NewResponse(&operatorv1.StepUpResponse{}), nil
}
