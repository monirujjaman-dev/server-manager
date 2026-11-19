package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/ctl"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/auth"
	"github.com/monirujjaman-dev/server-manager/internal/server/secretbox"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
)

// newCredentials asks for a password and enrolls TOTP, verifying one code before
// returning, so the user cannot be locked out by a mistyped secret.
func newCredentials(cmd *cobra.Command, account string) (string, []byte, error) {
	out := cmd.ErrOrStderr()
	pw, err := ctl.ReadSecret(out, "New password: ")
	if err != nil {
		return "", nil, err
	}
	if err := auth.CheckPassword(pw); err != nil {
		return "", nil, err
	}
	again, err := ctl.ReadSecret(out, "Repeat password: ")
	if err != nil {
		return "", nil, err
	}
	if again != pw {
		return "", nil, errors.New("passwords do not match")
	}
	secret, uri, err := auth.NewTOTP(account)
	if err != nil {
		return "", nil, err
	}
	_, _ = fmt.Fprintf(out, "\nAdd this account to an authenticator app (scan the URI as a QR code or type the secret):\n\n  %s\n  secret: %s\n\n", uri, auth.EncodeSecret(secret))
	for range 3 {
		code, err := ctl.ReadLine(out, "Code from the app: ")
		if err != nil {
			return "", nil, err
		}
		if _, ok := auth.MatchTOTP(secret, code, time.Now()); ok {
			return pw, secret, nil
		}
		_, _ = fmt.Fprintln(out, "That code does not match; check the device clock and try again.")
	}
	return "", nil, errors.New("TOTP enrollment not confirmed")
}

func authService(ctx context.Context, loadConfig func() (server.Config, error)) (*store.Store, *auth.Service, error) {
	st, cfg, err := openStore(ctx, loadConfig)
	if err != nil {
		return nil, nil, err
	}
	box, _, err := secretbox.LoadOrCreate(cfg.PKIDir)
	if err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("secrets key (run as the control-plane user): %w", err)
	}
	return st, auth.NewService(st, box, slog.New(slog.DiscardHandler)), nil
}

func usersCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "users", Short: "Manage operator accounts and roles"}

	var name, role, group string
	create := &cobra.Command{
		Use:   "create <email>",
		Short: "Create a user (prompts for a password and enrolls TOTP)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var r auth.Role
			if role != "" {
				var err error
				if r, err = auth.ParseRole(role); err != nil {
					return err
				}
			}
			st, svc, err := authService(ctx, loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			pw, secret, err := newCredentials(cmd, args[0])
			if err != nil {
				return err
			}
			u, err := svc.CreateUser(ctx, args[0], name, pw, secret, localActor())
			if err != nil {
				return err
			}
			if r != "" {
				if err := auth.Grant(ctx, st, u.ID, group, r, localActor()); err != nil {
					return err
				}
			}
			cmd.Printf("created %s (%s)\n", u.Email, u.ID)
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "display name")
	create.Flags().StringVar(&role, "role", "", "grant this role right away (viewer, operator, admin, owner)")
	create.Flags().StringVar(&group, "group", "", "server group for --role (default: all servers)")

	grant := &cobra.Command{
		Use:   "grant <email> <role>",
		Short: "Give a user a role on all servers or one group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := auth.ParseRole(args[1])
			if err != nil {
				return err
			}
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			u, err := auth.FindUser(cmd.Context(), st.Queries, args[0])
			if err != nil {
				return err
			}
			return auth.Grant(cmd.Context(), st, u.ID, group, r, localActor())
		},
	}
	grant.Flags().StringVar(&group, "group", "", "server group (default: all servers)")

	ungrant := &cobra.Command{
		Use:   "ungrant <email>",
		Short: "Remove a user's role on all servers (or on --group)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			u, err := auth.FindUser(cmd.Context(), st.Queries, args[0])
			if err != nil {
				return err
			}
			return auth.RemoveGrant(cmd.Context(), st, u.ID, group, localActor())
		},
	}
	ungrant.Flags().StringVar(&group, "group", "", "server group (default: the all-servers role)")

	list := &cobra.Command{
		Use: "list", Short: "List users and their roles", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			return listUsers(cmd.Context(), cmd.OutOrStdout(), st)
		},
	}

	setDisabled := func(disabled bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			u, err := auth.FindUser(cmd.Context(), st.Queries, args[0])
			if err != nil {
				return err
			}
			return auth.SetDisabled(cmd.Context(), st, u.ID, disabled, localActor())
		}
	}
	disable := &cobra.Command{Use: "disable <email>", Short: "Disable a user and end their sessions", Args: cobra.ExactArgs(1), RunE: setDisabled(true)}
	enable := &cobra.Command{Use: "enable <email>", Short: "Re-enable a user", Args: cobra.ExactArgs(1), RunE: setDisabled(false)}

	reset := &cobra.Command{
		Use:   "reset <email>",
		Short: "Set a new password and TOTP secret (for a lost device); ends all sessions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			st, svc, err := authService(ctx, loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			u, err := auth.FindUser(ctx, st.Queries, args[0])
			if err != nil {
				return err
			}
			pw, secret, err := newCredentials(cmd, u.Email)
			if err != nil {
				return err
			}
			if err := svc.ResetCredentials(ctx, u.ID, pw, secret, localActor()); err != nil {
				return err
			}
			cmd.Printf("credentials reset for %s\n", u.Email)
			return nil
		},
	}

	cmd.AddCommand(create, grant, ungrant, list, disable, enable, reset)
	return cmd
}

func listUsers(ctx context.Context, w io.Writer, st *store.Store) error {
	users, err := st.ListUsers(ctx)
	if err != nil {
		return err
	}
	bindings, err := st.ListAllRoleBindings(ctx)
	if err != nil {
		return err
	}
	roles := map[string][]string{}
	for _, b := range bindings {
		where := "all servers"
		if b.GroupName != nil {
			where = *b.GroupName
		}
		roles[b.UserID.String()] = append(roles[b.UserID.String()], b.Role+" on "+where)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "EMAIL\tSTATUS\tMFA\tLAST LOGIN\tROLES")
	for _, u := range users {
		status := "active"
		if u.DisabledAt != nil {
			status = "disabled"
		} else if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
			status = "locked"
		}
		mfa := "no"
		if u.TotpSecretEnc != nil {
			mfa = "totp"
		}
		last := "never"
		if u.LastLoginAt != nil {
			last = u.LastLoginAt.Local().Format(time.DateTime)
		}
		r := "-"
		if len(roles[u.ID.String()]) > 0 {
			r = fmt.Sprint(roles[u.ID.String()])
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Email, status, mfa, last, r)
	}
	return tw.Flush()
}
