//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// LoadP256PrivateKeyFromPEM loads a P-256 private key from PEM file
func LoadP256PrivateKeyFromPEM(filename string) (kem.PrivateKey, error) {
	// Read PEM file
	pemData, err := os.ReadFile(filename) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filename, err)
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", filename)
	}

	// Parse EC private key
	var ecdsaKey *ecdsa.PrivateKey

	// Try parsing as EC PRIVATE KEY
	if block.Type == "EC PRIVATE KEY" {
		ecdsaKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		// Try parsing as PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		ecdsaKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA private key")
		}
	} else {
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	// Verify it's P-256
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key uses curve %s, expected P-256", ecdsaKey.Curve.Params().Name)
	}

	// Convert to KEM private key format
	kemID := hpke.KEM_P256_HKDF_SHA256
	kemScheme := kemID.Scheme()

	// Convert ecdsa.PrivateKey to ecdh.PrivateKey and extract the raw scalar bytes.
	// ecdh.PrivateKey.Bytes() returns the 32-byte big-endian scalar for P-256,
	// matching the format expected by KEM_P256_HKDF_SHA256.
	ecdhPriv, err := ecdsaKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA key to ECDH key: %w", err)
	}
	dBytes := ecdhPriv.Bytes()

	// Unmarshal as KEM private key (just the 32-byte scalar for P-256)
	privKey, err := kemScheme.UnmarshalBinaryPrivateKey(dBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to KEM private key: %w", err)
	}

	return privKey, nil
}

// LoadP256PublicKeyFromCert loads a P-256 public key from certificate PEM file
func LoadP256PublicKeyFromCert(filename string) (kem.PublicKey, error) {
	// Read PEM file
	pemData, err := os.ReadFile(filename) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", filename, err)
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM from %s", filename)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract ECDSA public key
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain ECDSA public key")
	}

	// Verify it's P-256
	if ecdsaPubKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("certificate uses curve %s, expected P-256", ecdsaPubKey.Curve.Params().Name)
	}

	// Marshal to uncompressed point format using crypto/ecdh (avoids deprecated
	// elliptic.Marshal and the deprecated .X/.Y big.Int fields).
	ecdhPub, err := ecdsaPubKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ECDSA public key to ECDH key: %w", err)
	}
	pubKeyBytes := ecdhPub.Bytes()

	// Convert to KEM public key
	kemID := hpke.KEM_P256_HKDF_SHA256
	kemScheme := kemID.Scheme()
	pubKey, err := kemScheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to KEM public key: %w", err)
	}

	return pubKey, nil
}
