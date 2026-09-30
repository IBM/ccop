//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// logsCmd represents the logs command
var (
	logsCmd = &cobra.Command{
		Use:   "logs (POD | TYPE/NAME)",
		Short: "Print logs from a container (TBD)",
		Long: `Print logs from a container in a pod. If the pod has only one container, 
the container name is optional (TBD).

Examples:
  # Return snapshot logs from pod nginx with only one container
  ccop logs nginx
  
  # Return snapshot logs from pod nginx, prefixing each line with the source pod and container name
  ccop logs nginx --prefix

  # Begin streaming the logs of the ruby container in pod web-1
  ccop logs -f -c ruby web-1
 `,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("logs called (TBD)")
		},
	}
)

func init() {
	rootCmd.AddCommand(logsCmd)
}
