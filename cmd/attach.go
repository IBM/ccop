//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// attachCmd represents the attach command
var attachCmd = &cobra.Command{
	Use:   "attach (POD | TYPE/NAME)",
	Short: "Attach to a container's IO Streams (TBD)",
	Long: `Attach to a container's IO Streams (TBD).

Examples:
  # Attached to the first container in the pod
  ccop attach mypod -it
  
  # Get output from ruby-container from pod mypod
  ccop attach mypod -c ruby-container -it
  
  # Switch to raw terminal mode; sends stdin to 'bash' in ruby-container from pod mypod
  # and sends stdout/stderr from 'bash' back to the client
  ccop attach mypod -c ruby-container -i -t
  
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("attach called (TBD)")
	},
}

func init() {
	rootCmd.AddCommand(attachCmd)
}
