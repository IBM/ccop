//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// cpCmd represents the cp command
var (
	cpCmd = &cobra.Command{
		Use:   "cp",
		Short: "Copy files and directories to and from containers (TBD)",
		Long: `Copy files and directories to and from containers (TBD).

Examples:
  # !!!Important Notes!!!
  #
  #  (1) Requires 'sh' and 'tar' binaries to be present in your container
  #      Image.  If they are not present, 'ccop cp' will fail.
  #  (2) Only supports remote file copy, not directory

  # Copy /tmp/foo_dir local directory to /tmp/bar_dir in a remote pod in the default namespace
  ccop cp /tmp/foo_dir <some-pod>:/tmp/bar_dir
  
  # Copy /tmp/foo local file to /tmp in a remote pod in a specific container
  ccop cp /tmp/foo <some-pod>:/tmp -c <specific-container>
  
  # Copy /tmp/foo local file to /tmp in a remote pod in namespace <some-namespace>
  ccop cp /tmp/foo <some-namespace>/<some-pod>:/tmp
  
  # Copy /tmp/foo from a remote pod to /tmp/bar locally
  ccop cp <some-namespace>/<some-pod>:/tmp/foo /tmp/bar`,

		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("cp called (TBD)")
		},
	}
)

func init() {
	rootCmd.AddCommand(cpCmd)
}
