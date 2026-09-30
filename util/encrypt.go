//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"
)

func GetTimeStamp() uint64 {
	currentTime := time.Now()
	timeStamp := currentTime.Unix()
	return uint64(timeStamp) // #nosec G115 -- time.Unix() is always non-negative
}

func GenerateRandomBytes(size int) []byte {

	nonce := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return nonce
}

func CreateKey(keysize int) []byte {
	key := GenerateRandomBytes(keysize)
	return key
}

func CreateIV() []byte {
	iv := GenerateRandomBytes(aes.BlockSize)
	return iv
}
func CreateZeroIV() []byte {
	iv := make([]byte, aes.BlockSize)
	return iv
}

func CreateNonce(key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := GenerateRandomBytes(aesgcm.NonceSize())
	return nonce
}

func AESencrypt(key, nonce []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nil
}

func AESdecrypt(key, nonce, encryptedB64 []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, encryptedB64, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

func AESCtrStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	return stream, nil
}

func EncodeDecode(stream cipher.Stream, chunk []byte) []byte {
	// process chunk could  be plaintext or ciphertext
	processedChunk := make([]byte, len(chunk))

	// XOR the chunk to get plaintext/ciphertext
	stream.XORKeyStream(processedChunk, chunk)
	return processedChunk
}

func KubectlMsg(chunk []byte) (bool, bool) {
	// Filters kubectl messages
	var lineBuf []byte
	var endSession = true

	for _, b := range chunk {
		if b == '\n' {
			line := string(lineBuf)
			//fmt.Printf("KubectlMsg: %s \n", line)

			if strings.HasPrefix(line, "command terminated with exit code") {
				fmt.Printf("%s", line)
				return true, endSession
			}
			// starting exec terminal with -it
			// starting attach
			//if strings.HasPrefix(line, "If you don't see a command prompt, try pressing enter.") {
			if strings.HasPrefix(line, "If you don't see a command prompt") {
				fmt.Printf("%s", line)
				return true, false
			}

			if strings.HasPrefix(line, "Error from server (NotFound)") {
				fmt.Printf("%s", line)
				return true, endSession
			}

			if strings.HasPrefix(line, "Session ended, resume using 'kubectl attach") {
				fmt.Printf("%s", line)
				return true, endSession
			}

			if strings.HasPrefix(line, "error: error stream protocol error: unknown error") {
				fmt.Printf("%s", line)
				return true, endSession
			}
			// when the command is no found, e.g., /bin/foobar
			if strings.HasPrefix(line, "error: Internal error occurred:") {
				fmt.Printf("%s", line)
				return true, endSession
			}

			lineBuf = lineBuf[:0]
		} else {
			lineBuf = append(lineBuf, b)
		}
	}
	// 	   isItKubectlMsg, isItAnEndSession
	return false, false
}

func AESGcmBlock(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
