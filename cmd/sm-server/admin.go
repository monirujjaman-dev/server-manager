package main

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/enroll"
	"github.com/monirujjaman-dev/server-manager/internal/server/fleet"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Admin commands run on the control-plane host and talk to the database directly.
// Access is controlled by who can read the configuration and database credentials;
// the operator API with user authentication arrives with RBAC in Phase 1.

func localActor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return "local:" + name
}

func openStore(ctx context.Context, loadConfig func() (server.Config, error)) (*store.Store, server.Config, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, cfg, err
	}
	if cfg.DatabaseURL == "" {
		return nil, cfg, errors.New("database_url is not set (config file or SM_DATABASE_URL)")
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	return st, cfg, err
}

func enrollCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "enroll", Short: "Manage agent enrollment"}
	var name, group string
	var ttl time.Duration
	create := &cobra.Command{
		Use:   "create-token",
		Short: "Create a one-time token that enrolls one server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, cfg, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			certs, err := pki.ReadCertFile(filepath.Join(cfg.PKIDir, pki.ServerCertFile))
			if err != nil {
				return fmt.Errorf("read server certificate for the pin: %w", err)
			}
			tok, err := enroll.CreateToken(cmd.Context(), st, enroll.TokenRequest{
				ServerName: name, GroupName: group, TTL: ttl, Actor: localActor(),
			})
			if err != nil {
				return err
			}
			apiURL := cfg.PublicAPIURL
			if apiURL == "" {
				apiURL = "https://<control-plane-host>:8444"
			}
			pin := pki.SPKIFingerprint(certs[0])
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Enrollment token for %q (single use, expires %s):\n\n  %s\n\n",
				tok.ServerName, tok.ExpiresAt.Local().Format(time.RFC1123), tok.Value)
			_, _ = fmt.Fprintf(out, "Run on the new server as root:\n\n  sm-agent enroll --server %s \\\n    --pin %s \\\n    --token %s\n\n",
				apiURL, pin, tok.Value)
			_, _ = fmt.Fprintln(out, "The token is shown only once. Treat it like a password until it is used or expires.")
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "server name (a-z, 0-9, '.', '-')")
	create.Flags().StringVar(&group, "group", "", "server group (optional)")
	create.Flags().DurationVar(&ttl, "ttl", enroll.DefaultTokenTTL, "token lifetime (1m to 24h)")
	_ = create.MarkFlagRequired("name")
	cmd.AddCommand(create)
	return cmd
}

func serversCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "servers", Short: "List and revoke managed servers"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List servers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			servers, err := st.ListServers(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tSTATUS\tHOSTNAME\tOS\tAGENT\tLAST SEEN\tID")
			for _, s := range servers {
				seen := "never"
				if s.LastSeenAt != nil {
					seen = time.Since(*s.LastSeenAt).Round(time.Second).String() + " ago"
				}
				osName := strings.TrimSpace(s.Distro + " " + s.DistroVersion)
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.Status, s.Hostname, osName, s.AgentVersion, seen, s.ID)
			}
			return tw.Flush()
		},
	})
	var reason string
	revoke := &cobra.Command{
		Use:   "revoke <name|id>",
		Short: "Revoke a server: its certificates stop working and its agent is disconnected",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, cfg, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			s, err := fleet.Resolve(cmd.Context(), st.Queries, args[0])
			if err != nil {
				return err
			}
			if err := fleet.Revoke(cmd.Context(), st, s.ID, localActor(), reason); err != nil {
				return err
			}
			cmd.Printf("revoked %s (%s). New connections are refused now; an open connection closes within %s.\n",
				s.Name, s.ID, cfg.HeartbeatInterval)
			return nil
		},
	}
	revoke.Flags().StringVar(&reason, "reason", "", "reason, recorded in the audit log")
	_ = revoke.MarkFlagRequired("reason")
	cmd.AddCommand(revoke)
	return cmd
}

func groupsCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "groups", Short: "Manage server groups"}
	cmd.AddCommand(&cobra.Command{
		Use:   "create <name>",
		Short: "Create a server group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			st, _, err := openStore(ctx, loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			tx, err := st.Pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			q := st.WithTx(tx)
			g, err := q.CreateServerGroup(ctx, args[0])
			if err != nil {
				return fmt.Errorf("create group (names: a-z, 0-9, '-'): %w", err)
			}
			if _, err := audit.Append(ctx, q, audit.Event{
				ActorType: audit.ActorUser, ActorID: localActor(), Action: "group.create",
				Params: map[string]string{"group": g.Name, "group_id": g.ID.String()}, Result: audit.Succeeded,
			}); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			cmd.Printf("created group %s (%s)\n", g.Name, g.ID)
			return nil
		},
	}, &cobra.Command{
		Use:   "list",
		Short: "List server groups",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			groups, err := st.ListServerGroups(cmd.Context())
			if err != nil {
				return err
			}
			for _, g := range groups {
				cmd.Printf("%s\t%s\n", g.Name, g.ID)
			}
			return nil
		},
	})
	return cmd
}

func auditCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect and verify the audit log"}
	var after int64
	var limit int32
	list := &cobra.Command{
		Use:   "list",
		Short: "List audit events in order",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			rows, err := st.ListAuditEvents(cmd.Context(), db.ListAuditEventsParams{AfterID: after, MaxRows: limit})
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tTIME\tACTOR\tACTION\tRESULT\tSERVER\tDETAILS")
			for _, r := range rows {
				server := ""
				if r.ServerID != nil {
					server = r.ServerID.String()
				}
				_, _ = fmt.Fprintf(tw, "%d\t%s\t%s:%s\t%s\t%s\t%s\t%s\n", r.ID, r.Ts.Local().Format(time.DateTime),
					r.ActorType, r.ActorID, r.Action, r.Result, server, string(r.Params))
			}
			return tw.Flush()
		},
	}
	list.Flags().Int64Var(&after, "after", 0, "show events after this ID")
	list.Flags().Int32Var(&limit, "limit", 100, "maximum number of events")
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Recompute the hash chain and report tampering",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore(cmd.Context(), loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			n, err := audit.Verify(cmd.Context(), st.Queries)
			if err != nil {
				return fmt.Errorf("%w (%d events verified before the break)", err, n)
			}
			cmd.Printf("audit chain OK: %d events verified\n", n)
			return nil
		},
	}
	cmd.AddCommand(list, verify)
	return cmd
}
