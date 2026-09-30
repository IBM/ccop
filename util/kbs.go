//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const kbsURLPrefix = "kbs/v0"
const adminTokenExpirySecs = 7200

// ClientSecret mirrors the JSON returned by the secretprov client_creds endpoint.
// The material_type tag drives which fields are populated; for P256 the
// public material is in CertPEM, for Random it is in Bytes.
type ClientSecret struct {
	SecretName   string `json:"secret_name"`
	SecretType   string `json:"secret_type"`
	MaterialType string `json:"material_type"`
	// P256
	CertPEM []byte `json:"cert_pem,omitempty"`
	// Symmetric
	Key []byte `json:"key,omitempty"`
	// Random
	Bytes []byte `json:"bytes,omitempty"`
	// TLS / Ed25519 / RSA public material
	PublicKey  []byte `json:"public_key,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	Cert       []byte `json:"cert,omitempty"`
	CACert     []byte `json:"ca_cert,omitempty"`
}

// signAdminToken produces a minimal EdDSA JWT (header.claims.sig) signed
// with the Ed25519 private key read from keyPEM. No third-party JWT library
// is required — the format is simple enough to build by hand.
func signAdminToken(keyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from auth key")
	}

	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	ed25519Key, ok := pkcs8Key.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("auth key is not an Ed25519 private key")
	}

	now := time.Now().Unix()

	// Header: {"alg":"EdDSA","typ":"JWT"}
	headerJSON := `{"alg":"EdDSA","typ":"JWT"}`
	// Claims: {"iat":<now>,"exp":<now+7200>}
	claimsJSON := fmt.Sprintf(`{"iat":%d,"exp":%d}`, now, now+adminTokenExpirySecs)

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))

	signingInput := headerB64 + "." + claimsB64
	sig := ed25519.Sign(ed25519Key, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// FetchClientCreds calls POST kbs/v0/secretprov/client_creds?<query> and returns
// the parsed ClientSecret. authKeyPEM is the Ed25519 private key used to sign
// the admin JWT. kbsURL is the KBS server root URL (e.g. "http://host:8090").
func FetchClientCreds(kbsURL string, authKeyPEM string, query string) (*ClientSecret, error) {
	token, err := signAdminToken(authKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to sign admin token: %w", err)
	}

	url := fmt.Sprintf("%s/%s/secretprov/client_creds?%s", kbsURL, kbsURLPrefix, query)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)

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
