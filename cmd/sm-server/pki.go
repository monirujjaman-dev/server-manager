package main

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/google/uuid"
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

	var csrPath, idStr, outPath string
	signAgentCmd := &cobra.Command{
		Use:   "sign-agent",
		Short: "Sign an agent CSR created with `sm-agent keygen` (manual enrollment)",
		Long: `Sign an agent certificate request. The agent's private key never leaves the agent:
copy only the .csr file here and the resulting certificate back.

Phase 1 replaces this manual step with token-based enrollment.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if csrPath == "" || outPath == "" {
				return errors.New("--csr and --out are required")
			}
			id := uuid.New()
			if idStr != "" {
				var err error
				if id, err = uuid.Parse(idStr); err != nil {
					return fmt.Errorf("--id: %w", err)
				}
			}
			d, err := pkiDir()
			if err != nil {
				return err
			}
			ca, err := pki.LoadCA(d)
			if err != nil {
				return err
			}
			csr, err := pki.ReadCSRFile(csrPath)
			if err != nil {
				return err
			}
			cert, err := ca.SignAgentCSR(csr, id)
			if err != nil {
				return err
			}
			if err := pki.WriteCertFile(outPath, cert, ca.Intermediate); err != nil {
				return err
			}
			cmd.Printf("server id: %s\ncertificate: %s (valid until %s)\nCA for the agent: %s\n",
				id, outPath, cert.NotAfter.Format("2006-01-02"), filepath.Join(d, pki.RootCertFile))
			return nil
		},
	}
	signAgentCmd.Flags().StringVar(&csrPath, "csr", "", "agent CSR file")
	signAgentCmd.Flags().StringVar(&idStr, "id", "", "server UUID (default: generate a new one)")
	signAgentCmd.Flags().StringVar(&outPath, "out", "", "output certificate file")

	cmd.AddCommand(initCmd, issueServerCmd, signAgentCmd)
	return cmd
}
