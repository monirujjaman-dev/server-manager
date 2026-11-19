package main

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server"
)

func pkiCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "Manage the internal certificate authority",
	}
	cmd.PersistentFlags().StringVar(&dir, "dir", "", "PKI directory (default: pki_dir from config)")
	pkiDir := func() (string, error) {
		if dir != "" {
			return dir, nil
		}
		cfg, err := loadConfig()
		if err != nil {
			return "", err
		}
		return cfg.PKIDir, nil
	}

	var org string
	var dnsNames []string
	var ipStrs []string
	parseIPs := func() ([]net.IP, error) {
		var ips []net.IP
		for _, s := range ipStrs {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", s)
			}
			ips = append(ips, ip)
		}
		return ips, nil
	}
	issueServer := func(cmd *cobra.Command, d string, ca *pki.CA) error {
		ips, err := parseIPs()
		if err != nil {
			return err
		}
		cert, key, err := ca.IssueServerCert(dnsNames, ips)
		if err != nil {
			return err
		}
		if err := pki.SaveServerCert(d, ca, cert, key); err != nil {
			return err
		}
		cmd.Printf("server certificate: %s (valid until %s)\n", filepath.Join(d, pki.ServerCertFile), cert.NotAfter.Format("2006-01-02"))
		cmd.Printf("server key pin (SHA-256 SPKI): %s\n", pki.SPKIFingerprint(cert))
		return nil
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new CA and control-plane server certificate",
		Long: `Create a new root CA, intermediate CA and control-plane server certificate.

After init, move root.key to offline storage: it is only needed to issue a new
intermediate. The control plane runs with the intermediate key alone.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := pkiDir()
			if err != nil {
				return err
			}
			ca, err := pki.CreateCA(org)
			if err != nil {
				return err
			}
			if err := pki.SaveCA(d, ca); err != nil {
				return fmt.Errorf("save CA (refusing to overwrite an existing CA): %w", err)
			}
			cmd.Printf("created CA in %s\n", d)
			return issueServer(cmd, d, ca)
		},
	}
	initCmd.Flags().StringVar(&org, "org", "Server Manager", "organization name in certificates")

	issueServerCmd := &cobra.Command{
		Use:   "issue-server",
		Short: "Issue or renew the control-plane server certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := pkiDir()
			if err != nil {
				return err
			}
			ca, err := pki.LoadCA(d)
			if err != nil {
				return err
			}
			return issueServer(cmd, d, ca)
		},
	}
	for _, c := range []*cobra.Command{initCmd, issueServerCmd} {
		c.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS name for the server certificate (repeatable)")
		c.Flags().StringSliceVar(&ipStrs, "ip", nil, "IP address for the server certificate (repeatable)")
	}

	cmd.AddCommand(initCmd, issueServerCmd)
	return cmd
}
