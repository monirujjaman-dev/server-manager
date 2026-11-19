package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Role is a built-in role. Each role includes the ones below it.
type Role string

// Roles, from least to most privileged.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleOwner    Role = "owner"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3, RoleOwner: 4}

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if _, ok := roleRank[r]; !ok {
		return "", fmt.Errorf("unknown role %q (viewer, operator, admin, owner)", s)
	}
	return r, nil
}

// minRoleFor is the least role allowed to run an action of a risk level.
func minRoleFor(risk command.Risk) Role {
	switch risk {
	case command.RiskRead:
		return RoleViewer
	case command.RiskLow, command.RiskMedium:
		return RoleOperator
	case command.RiskHigh:
		return RoleAdmin
	default:
		return RoleOwner
	}
}

// NeedsStepUp reports whether a risk level requires a recent TOTP check.
func NeedsStepUp(risk command.Risk) bool {
	return risk == command.RiskHigh || risk == command.RiskCritical
}

// Errors returned by authorization.
var (
	ErrForbidden      = errors.New("permission denied")
	ErrStepUpRequired = errors.New("this action needs a fresh MFA code (step-up)")
)

// Grants is a user's effective roles.
type Grants struct {
	Global Role               // "" if none
	Groups map[uuid.UUID]Role // per server group
}

// RoleFor returns the effective role on a server in group (nil = no group).
func (g Grants) RoleFor(group *uuid.UUID) Role {
	best := g.Global
	if group != nil {
		if r, ok := g.Groups[*group]; ok && roleRank[r] > roleRank[best] {
			best = r
		}
	}
	return best
}

// Has reports whether the effective role on group is at least want.
func (g Grants) Has(group *uuid.UUID, want Role) bool {
	return roleRank[g.RoleFor(group)] >= roleRank[want]
}

// CanSee reports whether the user may see a server in group at all.
func (g Grants) CanSee(group *uuid.UUID) bool { return g.Has(group, RoleViewer) }

// LoadGrants reads a user's role bindings.
func LoadGrants(ctx context.Context, q *db.Queries, userID uuid.UUID) (Grants, error) {
	rows, err := q.ListRoleBindings(ctx, userID)
	if err != nil {
		return Grants{}, err
	}
	g := Grants{Groups: map[uuid.UUID]Role{}}
	for _, r := range rows {
		role := Role(r.Role)
		if r.GroupID == nil {
			if roleRank[role] > roleRank[g.Global] {
				g.Global = role
			}
			continue
		}
		g.Groups[*r.GroupID] = role
	}
	return g, nil
}

// AuthorizeAction checks role and, for high-risk actions, step-up.
func AuthorizeAction(g Grants, p Principal, server db.Server, risk command.Risk, now time.Time) error {
	if !g.Has(server.GroupID, minRoleFor(risk)) {
		return fmt.Errorf("%w: %s-risk actions on %s need the %s role", ErrForbidden, risk, server.Name, minRoleFor(risk))
	}
	if NeedsStepUp(risk) && !p.RecentMFA(now) {
		return ErrStepUpRequired
	}
	return nil
}
