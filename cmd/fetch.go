//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"ccop/util"
)

var (
	cliFetchURL        string
	cliFetchAuthKey    string
	cliFetchNameSpace  string
	cliFetchPodName    string
	cliFetchOutputFile string

	fetchCmd = &cobra.Command{
		Use:   "fetch",
		Short: "Fetch certificate from Trustee (KBS)",
		Long: `Fetch a P-256 certificate from the Key Broker Service (Trustee) secretprov plugin
and save it to the local cache or a specified output file.

The certificate is retrieved using the client_creds endpoint, which requires
a KBS admin Ed25519 private key for JWT authentication.

The query sent to KBS is built from --namespace and --pod as:
  name=<pod>&ns=<namespace>
Additional key=value parameters (e.g. secret_name and secret_type) must be
provided as positional arguments after all flags.

Examples:

  # Fetch the P-256 certificate for secret "grpc" belonging to pod pod-abc
  ccop fetch --url http://10.187.57.95:8090 --auth-key /path/to/private.key \
             --namespace default --pod pod-abc \
             secret_name=grpc secret_type=p256

  # Save to a custom output file instead of the default cache path
  ccop fetch --url http://10.187.57.95:8090 --auth-key /path/to/private.key \
             --namespace default --pod pod-abc --out /tmp/receiver.crt \
             secret_name=grpc secret_type=p256
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := processFetch(args); err != nil {
				log.Fatalf("error: %v", err)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().StringVar(&cliFetchURL, "url", "http://127.0.0.1:8080", "KBS server root URL")
	fetchCmd.PersistentFlags().StringVar(&cliFetchAuthKey, "auth-key", "", "Ed25519 admin private key file (PEM) for KBS authentication")
	fetchCmd.PersistentFlags().StringVarP(&cliFetchNameSpace, "namespace", "n", "default", "Kubernetes namespace")
	fetchCmd.PersistentFlags().StringVar(&cliFetchPodName, "pod", "", "Pod name")
	fetchCmd.PersistentFlags().StringVar(&cliFetchOutputFile, "out", "", "Output file path for the certificate (optional; overrides cache path)")

	_ = fetchCmd.MarkPersistentFlagRequired("auth-key") // #nosec G104 -- only fails if flag name is wrong (programming error)
	_ = fetchCmd.MarkPersistentFlagRequired("pod")      // #nosec G104
}

func processFetch(args []string) error {
	// Build query string from --namespace and --pod, then append any
	// extra key=value positional arguments (e.g. "spec=p256:1").
	query := fmt.Sprintf("name=%s&ns=%s", cliFetchPodName, cliFetchNameSpace)
	for _, extra := range args {
		query += "&" + extra
	}

	// Read the admin private key
	authKeyPEM, err := os.ReadFile(cliFetchAuthKey) // #nosec G304 -- path supplied by trusted CLI flag
	if err != nil {
		return fmt.Errorf("failed to read auth key file %q: %w", cliFetchAuthKey, err)
	}

	// Fetch from KBS
	secret, err := util.FetchClientCreds(cliFetchURL, string(authKeyPEM), query)
	if err != nil {
		return fmt.Errorf("failed to fetch client credentials: %w", err)
	}

	if secret.MaterialType != "P256" {
		return fmt.Errorf("expected P256 material, got %q", secret.MaterialType)
	}

	certPEM := secret.CertPEM
	if len(certPEM) == 0 {
		return fmt.Errorf("server returned a P256 secret with empty cert_pem")
	}

	fmt.Printf("Fetched certificate for secret %q (%d bytes)\n", secret.SecretName, len(certPEM))

	// Determine where to write the certificate
	if cliFetchOutputFile != "" {
		if err := os.WriteFile(cliFetchOutputFile, certPEM, 0600); err != nil { // #nosec G703 -- path supplied by trusted CLI flag
			return fmt.Errorf("failed to write certificate to %q: %w", cliFetchOutputFile, err)
		}
		fmt.Printf("Certificate saved to %s\n", cliFetchOutputFile)
		return nil
	}

	// Default: save to ~/.ccop/cache/<ns>_<pod>/receiver.crt
	if cliFetchPodName == "" {
		return fmt.Errorf("either --pod <name> (for cache path) or --out <file> must be specified")
	}

	certPath, err := util.SaveCertToCache(cliFetchNameSpace, cliFetchPodName, certPEM)
	if err != nil {
		return fmt.Errorf("failed to save certificate to cache: %w", err)
	}

	fmt.Printf("Certificate saved to %s\n", certPath)
	return nil
}
