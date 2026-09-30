//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"ccop/util"
)

// configCmd represents the config command
var (
	cliCr         bool
	cliRe         bool
	cliList       bool
	cliPr         bool

	configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configure ccop command parameters",
		Long: `Configure ccop environment enabling sensitive command execution on
confidential containers workloads. For example:

# Create configuration directories and file(s) in user home directory
ccop config -c

# List running pods
ccop config -l  

# Check whether ccop is enabled for a running pod
ccop config -l mypod 

# Review configuration settings, e.g., owner's public and private key pair
ccop config -r

# Retrieve mypod's artifacts from the key broker service (KBS) specified in
# the initdata, requiring KBS's admin private key file. Artifacts include
# public key certificate associated with sandbox environment ..., 
# saving artifacts to the local cache 

ccop config  mypod --auth-key /path/to/private.key

# Remove dated pod artifacts
ccop config --prune 

`,
		Run: func(cmd *cobra.Command, args []string) {
			// fmt.Println("config called")
			if len(args) > 0 {
				cliPodName = args[0] // removes the need for -p flag
			}
			processConfig(args)
		},
	}
)

func init() {
	rootCmd.AddCommand(configCmd)

	configCmd.PersistentFlags().BoolVarP(&cliCr, "create", "c", false, "Create configuration template")
	configCmd.PersistentFlags().BoolVarP(&cliRe, "review", "r", false, "Review configuration settings")
	configCmd.PersistentFlags().BoolVarP(&cliList, "list", "l", false, "List running pods and relevant ccop initdata")
	configCmd.PersistentFlags().BoolVarP(&cliPr, "prune", "", false, "Delete pod artifacts")

	configCmd.PersistentFlags().StringVarP(&cliNameSpace, "namespace", "n", "default", "Namespace scope")
	configCmd.PersistentFlags().StringVar(&cliFetchAuthKey, "auth-key", "", "Ed25519 admin private key file (PEM) for KBS authentication")
}

func processConfig(cmdargs []string) {

	if cliCr {
		_, err := create()
		if err != nil {
			log.Fatalf("create error: %v", err)
		}
	}

	if cliRe {
		_, err := review()
		if err != nil {
			log.Fatalf("review error: %v", err)
		}
	}

	if cliList {
		if cliPodName == "" {
			if err := util.ListWorkload(); err != nil {
				log.Fatalf("list error: %v", err)
			}
		} else {
			if err := util.CheckCCOPEnabled(cliNameSpace, cliPodName, ""); err != nil {
				log.Fatalf("list error: %v", err)
			}
			fmt.Printf("%s is ccop enabled\n", cliPodName)
		}
	}

	if cliFetchAuthKey != "" {
		if cliPodName == "" {
			log.Fatalf("pod error: pod-name required ")
		}
		if err := util.CheckCCOPEnabled(cliNameSpace, cliPodName, cliFetchAuthKey); err != nil {
			log.Fatalf("retrieve error: %v", err)
		}

	}

	if cliPr {
		if err := prune(); err != nil {
			log.Fatalf("prune error: %v", err)
		}
	}
}

func create() (*util.UserConfig, error) {
	var cfg util.UserConfig

	cfgDir, err := util.GetCfgDir()

	if err != nil {
		return nil, err
	}

	// Check if directory exists
	if _, err := os.Stat(*cfgDir); err == nil {
		return nil, errors.New("directory ~/.ccop already exists. Exiting")
	}

	// Specify and create cache directory
	cachePath := filepath.Join(*cfgDir, "cache")
	err = os.MkdirAll(cachePath, 0750)
	if err != nil {
		return nil, err
	}

	// Specify and create simple configuration template
	cfgFile := filepath.Join(*cfgDir, "config.toml")

	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		defaultCfg := util.UserConfig{
			UserPublicKeyCert: "/path/to/user/publickey",
			UserPrivateKey:    "/path/to/user/privatekey",
		}

		file, err := os.Create(cfgFile) // #nosec G304 -- path is user config file under ~/.ccop
		if err != nil {
			return nil, err
		}
		defer file.Close()

		encoder := toml.NewEncoder(file)
		if err := encoder.Encode(defaultCfg); err != nil {
			return nil, err
		}

		return &defaultCfg, nil
	}

	return &cfg, nil
}

func review() (*util.UserConfig, error) {
	userCfg, err := util.GetCfgFile()
	if err != nil {
		return nil, err
		//log.Fatalf("create error: %v", err)
	}

	if _, err := os.Stat(userCfg.UserPublicKeyCert); os.IsNotExist(err) {
		return nil, fmt.Errorf("doesn't exist: %s", userCfg.UserPublicKeyCert)
	}
	fmt.Println("UserPublicKeyCert:", userCfg.UserPublicKeyCert)

	if _, err := os.Stat(userCfg.UserPrivateKey); os.IsNotExist(err) {
		return nil, fmt.Errorf("doesn't exist: %s", userCfg.UserPrivateKey)
	}
	fmt.Println("UserPrivateKey:", userCfg.UserPrivateKey)

	return userCfg, nil
}

func prune() error {
	return util.PruneCache()
}
