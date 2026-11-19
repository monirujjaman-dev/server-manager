package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
)

func migrateCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Manage the database schema (database_url / SM_DATABASE_URL)",
	}
	open := func() (*store.Migrator, error) {
		cfg, err := loadConfig()
		if err != nil {
			return nil, err
		}
		if cfg.DatabaseURL == "" {
			return nil, errors.New("database_url is not set (config file or SM_DATABASE_URL)")
		}
		return store.NewMigrator(cfg.DatabaseURL)
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := open()
			if err != nil {
				return err
			}
			defer func() { _ = m.Close() }()
			n, err := m.Up(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Printf("applied %d migration(s)\n", n)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "down",
		Short: "Roll back the most recent migration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := open()
			if err != nil {
				return err
			}
			defer func() { _ = m.Close() }()
			return m.Down(cmd.Context())
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := open()
			if err != nil {
				return err
			}
			defer func() { _ = m.Close() }()
			st, err := m.Status(cmd.Context())
			if err != nil {
				return err
			}
			for _, s := range st {
				state := "pending"
				if s.Applied {
					state = "applied"
				}
				cmd.Println(fmt.Sprintf("%05d  %-8s  %s", s.Version, state, s.Name))
			}
			return nil
		},
	})
	return cmd
}
