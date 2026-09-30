//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

type AAD struct {
	Version       uint8
	NameSpace     string
	PodName       string
	ContainerName string
	Timestamp     uint64
}

// ChannelKeys holds derived keys for secure channel communication
type ChannelKeys struct {
	EncryptKey []byte // 32 bytes for AES-256
	DecryptKey []byte // 32 bytes for AES-256
	EncryptIV  []byte // 12 bytes nonce for AES-GCM
	DecryptIV  []byte // 12 bytes nonce for AES-GCM
}
type EncryptedMessage struct {
	EncapsulatedKey []byte // Ephemeral public key
	Ciphertext      []byte // Encrypted payload
}

// PartyContext holds the HPKE sender context for key derivation
type PartyContext struct {
	Message *EncryptedMessage
	Sealer  hpke.Sealer
}

var HPKEConfig = hpke.NewSuite(
	hpke.KEM_P256_HKDF_SHA256, // KEM using P-256 curve
	hpke.KDF_HKDF_SHA256,      // KDF using HKDF-SHA256
	hpke.AEAD_AES256GCM,       // AEAD using AES-256-GCM
)

func EncodeAAD(a AAD) []byte {
	buf := new(bytes.Buffer)

	// write version
	buf.WriteByte(a.Version)

	// write namespace
	_ = binary.Write(buf, binary.BigEndian, uint16(len(a.NameSpace))) // #nosec G115 G104 -- namespace ≤ 253 chars; bytes.Buffer.Write never errors
	buf.WriteString(a.NameSpace)

	// write podName
	_ = binary.Write(buf, binary.BigEndian, uint16(len(a.PodName))) // #nosec G115 G104 -- pod name ≤ 253 chars; bytes.Buffer.Write never errors
	buf.WriteString(a.PodName)

	// write containerName
	_ = binary.Write(buf, binary.BigEndian, uint16(len(a.ContainerName))) // #nosec G115 G104 -- container name ≤ 253 chars; bytes.Buffer.Write never errors
	buf.WriteString(a.ContainerName)

	//  write Timestamp
	_ = binary.Write(buf, binary.BigEndian, a.Timestamp) // #nosec G104 -- bytes.Buffer.Write never errors

	return buf.Bytes()
}

// Sender performs HPKE authenticated encryption and returns context for key derivation
func HPKEAuthEncryptWithContext(
	senderPrivateKey kem.PrivateKey,
	receiverPublicKey kem.PublicKey,
	plaintext []byte,
	aad []byte, // Additional Authenticated Data
	info []byte, // Context information
) (*PartyContext, error) {

	// Create sender context in Auth mode
	sender, err := HPKEConfig.NewSender(receiverPublicKey, info)
	if err != nil {
		return nil, fmt.Errorf("failed to create sender context: %w", err)
	}

	// Setup with authentication using sender's private key
	encapsulatedKey, sealer, err := sender.SetupAuth(rand.Reader, senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup auth sender: %w", err)
	}

	// Seal (encrypt and authenticate) the plaintext with AAD
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to seal plaintext: %w", err)
	}

	return &PartyContext{
		Message: &EncryptedMessage{
			EncapsulatedKey: encapsulatedKey,
			Ciphertext:      ciphertext,
		},
		Sealer: sealer,
	}, nil
}

// Receiver performs HPKE authenticated encryption and returns context for key derivation
func HPKEAuthDecryptWithContext(
	receiverPrivateKey kem.PrivateKey,
	senderPublicKey kem.PublicKey,
	encapsulatedKey []byte,
	ciphertext []byte,
	aad []byte, // Additional Authenticated Data (must match encryption)
	info []byte, // Context information (must match encryption)
) ([]byte, hpke.Opener, error) {

	// Create receiver context in Auth mode
	receiver, err := HPKEConfig.NewReceiver(receiverPrivateKey, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create receiver context: %w", err)
	}

	// Setup with authentication verification using sender's public key
	opener, err := receiver.SetupAuth(encapsulatedKey, senderPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup auth receiver (authentication failed): %w", err)
	}

	// Open (decrypt and verify) the ciphertext with AAD
	plaintext, err := opener.Open(ciphertext, aad)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to open ciphertext (decryption/verification failed): %w", err)
	}

	return plaintext, opener, nil
}

func DeriveChannelIV(sealer hpke.Sealer) ([]byte, error) {
	return sealer.Export([]byte("channel-encrypt-iv"), 12), nil
}

func DeriveChannelEncryptKey(sealer hpke.Sealer) ([]byte, error) {
	return sealer.Export([]byte("channel-encrypt-key"), 32), nil
}

func DeriveChannelKeys(sealer hpke.Sealer) (*ChannelKeys, error) {
	// Export 88 bytes total: 32+32+12+12
	// Context strings differentiate the keys

	// Derive encryption key (sender -> receiver)
	encryptKey := sealer.Export([]byte("channel-encrypt-key"), 32)

	// Derive decryption key (receiver -> sender)
	decryptKey := sealer.Export([]byte("channel-decrypt-key"), 32)

	// Derive encryption IV/nonce
	encryptIV := sealer.Export([]byte("channel-encrypt-iv"), 16)

	// Derive decryption IV/nonce
	decryptIV := sealer.Export([]byte("channel-decrypt-iv"), 16)

	return &ChannelKeys{
		EncryptKey: encryptKey,
		DecryptKey: decryptKey,
		EncryptIV:  encryptIV,
		DecryptIV:  decryptIV,
	}, nil
}
func DeriveChannelKeysFromOpener(opener hpke.Opener) (*ChannelKeys, error) {
	// Export same keys using same context strings
	// Note: In HPKE, both sender and receiver derive the same keys
	// Receiver swaps operations
	encryptKey := opener.Export([]byte("channel-decrypt-key"), 32)
	decryptKey := opener.Export([]byte("channel-encrypt-key"), 32)
	encryptIV := opener.Export([]byte("channel-decrypt-iv"), 16)
	decryptIV := opener.Export([]byte("channel-encrypt-iv"), 16)

	return &ChannelKeys{
		EncryptKey: encryptKey,
		DecryptKey: decryptKey,
		EncryptIV:  encryptIV,
		DecryptIV:  decryptIV,
	}, nil
}

// deriveAttachKeys derives independent block_key (32B), stream_key (32B), and iv (16B)
// from ikm using HKDF-SHA256 with distinct info strings, matching the Rust get_init_crypto
// implementation in cc-op/src/lib.rs.
func DeriveAttachLogsKeys(ikm []byte) (blockKey, streamKey, iv []byte, err error) {
	expand := func(info string, length int) ([]byte, error) {
		r := hkdf.New(sha256.New, ikm, nil, []byte(info))
		out := make([]byte, length)
		if _, err := io.ReadFull(r, out); err != nil {
			return nil, fmt.Errorf("hkdf expand %q: %w", info, err)
		}
		return out, nil
	}

	if blockKey, err = expand("ccop attach logs block-key v1", 32); err != nil {
		return
	}
	if streamKey, err = expand("ccop attach logs stream-key v1", 32); err != nil {
		return
	}
	iv, err = expand("ccop attach logs iv v1", 16)
	return
}

/*  Hybrid Public Key Exchange (HPKE) authenticated mode
	Assume:
	Tenant (Sender):
		private/public key pair (identity, used for signing)
		ephemeral key secret

	Host (Receiver):
	  	private/public key pair (encrypting) // self generated or trustee provisioned (CA)


Owner/Tenant(Sender)
--------------------
1. Generates ephemeral key (uses static keys and some randomness) per request!

	command = "/bin/sh "
	info = []byte("tenant->host command v1")
	aad = pod ID || container ID || timestamp || ... // metadata, associated data

    // Create sender context
	enc, senderCtx = suite.SetupAuthSender(
		rand.Reader,		// Makes it difference per-request!
		hostPubKey,
		info,
		tenantPrivKey
	)

	// Encrypt command (AAD is authenticated, not encrypted)
	ciphertext = senderCtx.Seal(command, aad)

2. Sends {metadata, enc and ciphertext} to Host (only --payload option is needed; No signature)

			Host
			----
			3. Uses its private key and tenant pubkey to decrypt command and verify aad:

					aad = pod ID || container ID || timestamp
					info = []byte("tenant->host command v1")

					// Create receiver context
					receiverCtx  = suite.SetupAuthReceiver(
						hostPrivKey,
						enc,
						info,
						tenantPubKey,
					)


					// Decrypt + integrity check
					plaintext = receiverCtx.Open(ciphertext, aad)


			4. Derives session keys from HPKE exporter
					encKey = receiverCtx.Export([]byte("enc key"), 32)
					macKey  = receiverCtx.Export([]byte("mac key"), 32)
					nonceBase = receiverCtx.Export([]byte("nonce"), 12)

Owner/Tenant
------------
5. Derives session keys from HPKE exporter
		encKey = receiverCtx.Export([]byte("enc key"), 32)
		macKey = receiverCtx.Export([]byte("mac key"), 32)
		nonceBase = receiverCtx.Export([]byte("nonce"), 12)


------------
|  Info:   |
------------


https://pkg.go.dev/github.com/aead/ecdh#section-readme
 	- ECDH implementations: NIST curves P224, P256, P384, and Bernstein's Cruve25519
*/
