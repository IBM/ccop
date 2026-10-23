//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const kbsURLPrefix = "kbs/v0"

// IntBytes is a []byte that deserialises from a JSON array of integers,
// which is how Rust's serde serialises Vec<u8>.
// Example wire format: [45, 45, 66, 69, 71, 73, 78, ...]
type IntBytes []byte

func (b *IntBytes) UnmarshalJSON(data []byte) error {
	var ints []int
	if err := json.Unmarshal(data, &ints); err != nil {
		return fmt.Errorf("IntBytes: expected JSON array of integers: %w", err)
	}
	*b = make([]byte, len(ints))
	for i, v := range ints {
		(*b)[i] = byte(v)
	}
	return nil
}

// ClientSecret mirrors the JSON returned by the credgen client_creds endpoint.
//
// The plugin serialises all byte fields as JSON arrays of integers (Rust
// serde's default for Vec<u8>), so every byte field uses IntBytes rather than
// []byte. The material_type tag identifies which fields are populated:
//
//	"Cert"       → Cert (+ PrivateKey, CACert for kind "leaf_cert")
//	"Asymmetric" → PublicKey
//	"Symmetric"  → Key
//
// Kind is set for certs only; Algorithm for certs and asymmetric keys.
type ClientSecret struct {
	SecretName   string `json:"secret_name"`
	SecretType   string `json:"secret_type"`
	Kind         string `json:"kind,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	MaterialType string `json:"material_type"`
	// Cert (PrivateKey and CACert only for kind "leaf_cert")
	PrivateKey IntBytes `json:"private_key,omitempty"`
	Cert       IntBytes `json:"cert,omitempty"`
	CACert     IntBytes `json:"ca_cert,omitempty"`
	// Asymmetric
	PublicKey IntBytes `json:"public_key,omitempty"`
	// Symmetric
	Key IntBytes `json:"key,omitempty"`
}

// FetchClientCreds calls POST kbs/v0/credgen/client_creds?<query> and returns
// the parsed ClientSecret. adminToken is the pre-issued KBS admin bearer token.
// kbsURL is the KBS server root URL (e.g. "http://host:8090").
func FetchClientCreds(kbsURL string, adminToken string, query string) (*ClientSecret, error) {
	url := fmt.Sprintf("%s/%s/credgen/client_creds?%s", kbsURL, kbsURLPrefix, query)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// The admin POST path in api_server.rs returns the raw plugin bytes directly
	// (no envelope). The kbs-client tool's {"credentials":...} wrapper is only
	// added by the CLI for display — it is not present in the HTTP response.
	var secret ClientSecret
	if err := json.Unmarshal(body, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w (body: %s)", err, body)
	}

	return &secret, nil
}

// SaveCertToCache writes the PEM certificate bytes for a P256 secret to
// ~/.ccop/cache/<ns>_<podname>/receiver.crt, creating the directory if needed.
func SaveCertToCache(ns string, podName string, certPEM []byte) (string, error) {
	return SaveBytesToCache(ns, podName, "receiver.crt", certPEM)
}

// SaveBytesToCache writes arbitrary bytes to ~/.ccop/cache/<ns>_<podname>/<filename>,
// creating the directory if needed.
func SaveBytesToCache(ns string, podName string, filename string, data []byte) (string, error) {
	cfgDir, err := GetCfgDir()
	if err != nil {
		return "", err
	}

	cacheDir := fmt.Sprintf("%s/cache/%s_%s", *cfgDir, ns, podName)
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create cache directory %s: %w", cacheDir, err)
	}

	filePath := fmt.Sprintf("%s/%s", cacheDir, filename)
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return filePath, nil
}
