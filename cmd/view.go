//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/spf13/cobra"
	"github.com/vmihailenco/msgpack/v5"

	"ccop/util"
)

// viewCmd represents the check command
var (
	cliPayload        string
	cliTestDecrypt    bool
	cliTestDeriveKeys bool
	cliTestError      bool

	viewCmd = &cobra.Command{
		Use:   "view",
		Short: "View a payload",
		Long: `View a payload
For example:
ccop view --payload <base64>`,
		Run: func(cmd *cobra.Command, args []string) {
			var payloadJSON, err = base64.StdEncoding.DecodeString(cliPayload)

			if err != nil {
				fmt.Println("Error base64 decode: ", err)
				return
			}

			var m Meta

			err = msgpack.Unmarshal(payloadJSON, &m)

			if err != nil {
				panic(err)
			}

			switch m.Type {
			/*
				case "A":
			*/
			case "C":
				var p PayloadMessage

				fmt.Println("Payload: ")
				displayPacked(payloadJSON)
				if err = msgpack.Unmarshal(payloadJSON, &p); err != nil {
					panic(err)
				}

				if cliTestDecrypt {
					userPublicKey, err := util.GetUserPubKeyFile(cliPubKeyCertFile)
					if err != nil {
						log.Fatalf("error: %v ", err)
					}

					recvPrivateKey, err := util.GetRecvPriKeyFile(cliPrivateFile, p.NameSpace, p.PodName)
					if err != nil {
						log.Fatalf("error: %v ", err)
					}

					spubkey, err := util.LoadP256PublicKeyFromCert(userPublicKey)
					if err != nil {
						log.Fatalf("error: %v ", err)
					}
					_ = spubkey

					rprivkey, err := util.LoadP256PrivateKeyFromPEM(recvPrivateKey)
					if err != nil {
						log.Fatalf("error: %v ", err)
					}

					cmdArgs, opener, err := decryptReturnCtx(p, rprivkey, spubkey)
					if err != nil {
						log.Fatalf("error: %v ", err)
					}
					fmt.Println("Args: ", cmdArgs)

					if cliTestDeriveKeys {
						channelKeys, err := util.DeriveChannelKeysFromOpener(opener)
						if err != nil {
							log.Fatalf("error: %v ", err)
						}
						fmt.Println("Derived channel keys: ", channelKeys)

					}

					if cliTestError {
						_, _, err = changeAADCtx(p, rprivkey, spubkey)
						if err != nil {
							fmt.Println("error: ", err)
						}

						_, _, err = changeEncapsulatedKeyCtx(p, rprivkey, spubkey)
						if err != nil {
							fmt.Println("error: ", err)
						}

						_, _, err = changeCiphertextCtx(p, rprivkey, spubkey)
						if err != nil {
							fmt.Println("error: ", err)
						}

					}

				}

			default:
				fmt.Println("Warning: unsupported type:", m)
			}
			//}
		},
	}
)

func init() {
	rootCmd.AddCommand(viewCmd)
	viewCmd.PersistentFlags().StringVar(&cliPubKeyCertFile, "pubkeycert", "", "(Optional) User public key certificate file (PEM)")
	viewCmd.PersistentFlags().StringVar(&cliPrivateFile, "privkey", "", "(Optional) Agent private key file (PEM)")
	viewCmd.PersistentFlags().StringVar(&cliPayload, "payload", "", "Base64 encoding of payload (JSON string)")
	_ = viewCmd.MarkPersistentFlagRequired("payload") // #nosec G104 -- only fails if flag name is wrong
	viewCmd.PersistentFlags().BoolVarP(&cliTestDecrypt, "decrypt", "", false, "Test: Agent (receiver) authenticate and decrypt, requiring --privkey option")
	viewCmd.PersistentFlags().BoolVarP(&cliTestDeriveKeys, "derive", "", false, "Test: Agent (receiver) derive channel keys, requiring --privkey option ")
	viewCmd.PersistentFlags().BoolVarP(&cliTestError, "error", "e", false, "Test for errors")
}

func decryptReturnCtx(p PayloadMessage, rPrivateKey kem.PrivateKey, sPublicKey kem.PublicKey) ([]string, hpke.Opener, error) {
	//func decryptReturnCtx(p PayloadMessage, rPrivateKey kem.PrivateKey, sPublicKey kem.PublicKey) (cmdArgs []string, opener hpke.Opener, e error) {
	info := []byte("ccop->agent command v1")

	var aad util.AAD
	var opener hpke.Opener

	aad.Version = 1
	aad.NameSpace = p.NameSpace
	aad.PodName = p.PodName
	aad.ContainerName = p.ContainerName
	aad.Timestamp = p.TimeStamp
	encoded_aad := util.EncodeAAD(aad)

	serializedArgs, opener, err := util.HPKEAuthDecryptWithContext(rPrivateKey, sPublicKey, p.EncapsulatedKey, p.Ciphertext, encoded_aad, info)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decrypt: %v", err)
	}

	cmdArgs, err := deserializeCommandArgs(serializedArgs)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to deserialize: %v", err)
	}

	return cmdArgs, opener, nil
}

func changeAADCtx(p PayloadMessage, rPrivateKey kem.PrivateKey, sPublicKey kem.PublicKey) ([]string, hpke.Opener, error) {
	info := []byte("ccop->agent command v1")

	var aad util.AAD
	var opener hpke.Opener

	aad.Version = 1
	aad.NameSpace = p.NameSpace
	//aad.PodName = p.PodName
	aad.PodName = "boxbusy"
	aad.ContainerName = p.ContainerName
	aad.Timestamp = p.TimeStamp
	encoded_aad := util.EncodeAAD(aad)

	fmt.Println("Change AAD PodName")
	serializedArgs, opener, err := util.HPKEAuthDecryptWithContext(rPrivateKey, sPublicKey, p.EncapsulatedKey, p.Ciphertext, encoded_aad, info)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}

	cmdArgs, err := deserializeCommandArgs(serializedArgs)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}
	fmt.Println("Args: ", cmdArgs)

	return cmdArgs, opener, nil
}

func changeEncapsulatedKeyCtx(p PayloadMessage, rPrivateKey kem.PrivateKey, sPublicKey kem.PublicKey) ([]string, hpke.Opener, error) {
	info := []byte("ccop->agent command v1")

	var aad util.AAD
	var opener hpke.Opener

	aad.Version = 1
	aad.NameSpace = p.NameSpace
	aad.PodName = p.PodName
	aad.ContainerName = p.ContainerName
	aad.Timestamp = p.TimeStamp
	encoded_aad := util.EncodeAAD(aad)

	if len(p.EncapsulatedKey) > 0 {
		fmt.Println("Change EncapsulatedKey first position")
		p.EncapsulatedKey[0] = 20
	}

	serializedArgs, opener, err := util.HPKEAuthDecryptWithContext(rPrivateKey, sPublicKey, p.EncapsulatedKey, p.Ciphertext, encoded_aad, info)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}

	cmdArgs, err := deserializeCommandArgs(serializedArgs)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}
	fmt.Println("Args: ", cmdArgs)

	return cmdArgs, opener, nil
}

func changeCiphertextCtx(p PayloadMessage, rPrivateKey kem.PrivateKey, sPublicKey kem.PublicKey) ([]string, hpke.Opener, error) {
	info := []byte("ccop->agent command v1")

	var aad util.AAD
	var opener hpke.Opener

	aad.Version = 1
	aad.NameSpace = p.NameSpace
	aad.PodName = p.PodName
	aad.ContainerName = p.ContainerName
	aad.Timestamp = p.TimeStamp
	encoded_aad := util.EncodeAAD(aad)

	if len(p.Ciphertext) > 0 {
		fmt.Println("Change Ciphertext last position")
		p.Ciphertext[len(p.Ciphertext)-1] = 20
	}

	serializedArgs, opener, err := util.HPKEAuthDecryptWithContext(rPrivateKey, sPublicKey, p.EncapsulatedKey, p.Ciphertext, encoded_aad, info)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}

	cmdArgs, err := deserializeCommandArgs(serializedArgs)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}
	fmt.Println("Args: ", cmdArgs)

	return cmdArgs, opener, nil
}
