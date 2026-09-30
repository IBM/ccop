//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type UserConfig struct {
	UserPublicKeyCert string
	UserPrivateKey    string
}

var zero32 = make([]byte, 32)

func GetRandomBytesFromFile(podname string, ns string) ([]byte, error) {
	var filename string
	subCache := "cache"
	cfgDir, err := GetCfgDir()

	if err != nil {
		return nil, err
	}

	subWorkload := ns + "_" + podname
	filename = "ccop_random.bin"
	byteFilename := filepath.Join(*cfgDir, subCache, subWorkload, filename)

	file, err := os.Open(byteFilename) // #nosec G304 -- path is constructed from validated config directory
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, 32)
	_, err = io.ReadFull(file, buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("failed to read: the file is completely empty")
		}
		return nil, fmt.Errorf("failed to read 32 bytes: %w", err)
	}

	// Check for all zeros
	if bytes.Equal(buf, zero32) {
		return nil, errors.New("failed to read: the data block contains only zeros")
	}

	return buf, nil
}

func GetdUserPrivKeyFile(filename string) (string, error) {
	var userPrivateKey string

	if filename != "" {
		// Check for key file
		_, err := os.Stat(filename)

		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}
		userPrivateKey = filename
	} else {
		userCfg, err := GetCfgFile()

		if err != nil {
			return "", fmt.Errorf("error: %v", err)
			//log.Fatalf("error: ", err)
		}
		userPrivateKey = userCfg.UserPrivateKey
	}
	return userPrivateKey, nil
}

func GetUserPubKeyFile(filename string) (string, error) {
	var userPublicKey string

	if filename != "" {
		// Check for key file
		_, err := os.Stat(filename)

		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}
		userPublicKey = filename
	} else {
		userCfg, err := GetCfgFile()

		if err != nil {
			return "", fmt.Errorf("error: %v", err)
		}
		userPublicKey = userCfg.UserPublicKeyCert
	}
	return userPublicKey, nil
}

func GetRecvPubKeyFile(filename string, ns string, podname string) (string, error) {
	var recvPubKeyFile string

	if filename != "" {
		// Check for key file
		_, err := os.Stat(filename)

		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}
		recvPubKeyFile = filename

	} else {
		pubKeyFile, err := getRecvKeyFile(ns, podname, true)

		if err != nil {
			return "", fmt.Errorf("error: %v", err)
		}
		recvPubKeyFile = *pubKeyFile

	}
	return recvPubKeyFile, nil
}

func GetRecvPriKeyFile(filename string, ns string, podname string) (string, error) {
	var recvPrivKeyFile string

	if filename != "" {
		// Check for key file
		_, err := os.Stat(filename)

		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %v", err)
		}
		recvPrivKeyFile = filename

	} else {
		pubKeyFile, err := getRecvKeyFile(ns, podname, false)

		if err != nil {
			return "", fmt.Errorf("error: %v", err)
		}
		recvPrivKeyFile = *pubKeyFile

	}
	return recvPrivKeyFile, nil
}

func GetCfgDir() (*string, error) {
	path, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}
	// Specify config directory
	cfgDir := filepath.Join(path, ".ccop")

	if _, err := os.Stat(cfgDir); os.IsNotExist(err) {
		return nil, err
	}

	return &cfgDir, nil
}

func GetCfgFile() (*UserConfig, error) {
	cfgDir, err := GetCfgDir()

	if err != nil {
		return nil, err
	}

	// Check if config.toml exists
	var userCfg UserConfig
	cfgFile := filepath.Join(*cfgDir, "config.toml")

	if _, err := toml.DecodeFile(cfgFile, &userCfg); err != nil {
		return nil, err
	}

	return &userCfg, nil
}

// func getPubKeyFile(ns string, podname string) (*string, error) {
func getRecvKeyFile(ns string, podname string, public bool) (*string, error) {
	var filename string
	subCache := "cache"
	cfgDir, err := GetCfgDir()

	if err != nil {
		return nil, err
	}

	// Check if cache/ns_podname/receiver.crt
	subWorkload := ns + "_" + podname
	if public {
		filename = "receiver.crt"
	} else {
		filename = "receiver.key"

	}
	keyPrivFilename := filepath.Join(*cfgDir, subCache, subWorkload, filename)

	if _, err := os.Stat(keyPrivFilename); os.IsNotExist(err) {
		return nil, err
	}
	return &keyPrivFilename, nil
}

func ProcessInput(chunk []byte) []byte {
	return chunk
}

func ProcessOutput(chunk []byte) []byte {
	return chunk
}
