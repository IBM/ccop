//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func SignB64(inputBytes []byte, privateKeyFile string) ([]byte, error) {
	keyBytes, err := os.ReadFile(privateKeyFile) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(keyBytes))
	if block == nil {
		return nil, fmt.Errorf("no PEM data found returned error %w", err)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(inputBytes))

	sigDER, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	return sigDER, nil
}

func VerifySignatureB64(pubKeyFile, payload, signature string, display bool) {
	keyBytes, err := os.ReadFile(pubKeyFile) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		fmt.Println("Error reading key")
		return
	}

	block, _ := pem.Decode([]byte(keyBytes))
	if block == nil {
		fmt.Println("Error Decode")
		return
	}

	// parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		//return false, fmt.Errorf("parse certificate: %w", err)
		fmt.Println("Error parsing key")
		return
	}

	// extract ECDSA public key
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		//return false, errors.New("certificate public key is not ECDSA")
		fmt.Println("Error it not a ECDSA")
		return
	}

	/*
		x509EncodedPub := block.Bytes

		publicKeyObj, err := x509.ParsePKIXPublicKey(x509EncodedPub)

		if err != nil {
			//return false, fmt.Errorf("parse public key: %w", err)
			fmt.Println("parse public key: %w", err)
			return
		}

		publicKey, ok := publicKeyObj.(*ecdsa.PublicKey)

		if !ok {
			fmt.Println("public key is not ECDSA")
			return
		}
	*/
	sig, err := base64.StdEncoding.DecodeString(signature)

	if err != nil {
		//return false, fmt.Errorf("decode signature base64: %w", err)
		fmt.Println("Error decode signature")
		return
	}
	// payload(b64) -> JSON bytes
	jsonBytes, err := base64.StdEncoding.DecodeString(payload)

	if err != nil {
		//return false, fmt.Errorf("decode signature base64: %w", err)
		fmt.Println("Error decode signature")
		return
	}

	hash := sha256.Sum256([]byte(jsonBytes))

	if display {
		fmt.Printf("hash %x\n", hash)
		fmt.Printf("signature %x\n", sig)

	}

	//r := new(big.Int).SetBytes(sig[:len(sig)/2])
	//s := new(big.Int).SetBytes(sig[len(sig)/2:])

	//if ecdsa.VerifyASN1(pubKey, hash[:], sig) {
	// if ecdsa.VerifyASN1(publicKey, hash[:], sig) {
	//if ecdsa.Verify(pubKey, hash[:], r, s)

	if ecdsa.VerifyASN1(pubKey, hash[:], sig) {

		fmt.Println("Verification success")
	} else {
		fmt.Println("Verification failed")

	}
}
