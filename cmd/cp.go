//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Intial command to discovery destination type
const resolveDestinationScript = `
case "$1" in
    /)
        printf '%s\n' directory
        ;;
    *)
        if [ -d "$1" ]; then
            printf '%s\n' directory
        elif [ -f "$1" ]; then
            printf '%s\n' file
        elif [ -e "$1" ]; then
            printf '%s\n' other
        else
            printf '%s\n' nonexistent
        fi
        ;;
esac
`

// cpCmd represents the cp command
var (
	cpCmd = &cobra.Command{
		Use:   "cp",
		Short: "Copy files and directories to and from containers",
		Long: `Copy files and directories to and from containers.

Examples:
  # !!!Important Note!!!
  #
  #  Requires 'sh' and 'tar' binaries to be present in your container
  #  image.  If they are not present, 'ccop cp' will fail.

  # Copy /tmp/foo_dir local directory to /tmp/bar_dir in a remote pod in the default namespace
  ccop cp /tmp/foo_dir <some-pod>:/tmp/bar_dir
  
  # Copy /tmp/foo local file to /tmp in a remote pod in a specific container
  ccop cp /tmp/foo <some-pod>:/tmp -c <specific-container>
  
  # Copy /tmp/foo local file to /tmp in a remote pod in namespace <some-namespace>
  ccop cp /tmp/foo <some-namespace>/<some-pod>:/tmp
  
  # Copy /tmp/foo from a remote pod to /tmp/bar locally
  ccop cp <some-namespace>/<some-pod>:/tmp/foo /tmp/bar`,

		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 2 {
				fmt.Println("error: source and destination are required")
				os.Exit(1)
			}
			src := args[0]
			dst := args[1]
			processCmdCpCcop(src, dst) // integrates ccop and kubectl calls!
		},
	}
)

func init() {
	rootCmd.AddCommand(cpCmd)
	cpCmd.PersistentFlags().BoolVarP(&cliDisplay, "display", "d", false, "Display kubectl command line")
	cpCmd.PersistentFlags().BoolVarP(&cliDry, "dryrun", "", false, "Dry run doesn't invoke kubectl")
	cpCmd.PersistentFlags().StringVarP(&cliContainerName, "container", "c", "", "Container name or ID")
	cpCmd.PersistentFlags().StringVar(&cliPrivateFile, "privkey", "", "(Optional) User private key file (PEM) for HPKE authenticated encryption")
	cpCmd.PersistentFlags().StringVar(&cliPubKeyCertFile, "pubkeycert", "", "(Optional) Agent public key certificate file (PEM) for HPKE authenticated encryption")
}

func processCmdCpCcop(src string, dst string) {
	var firstCmd []string
	var secondCmd []string
	var args []string
	var cmdStr string
	var stderr bytes.Buffer
	var c1, c2 *exec.Cmd

	left, lNS, lPod, lsrc, err := get_pod_info(src) // source (left)
	if err != nil {
		log.Fatalf("error: parsing file src spec: %v", err)
	}

	right, rNS, rPod, rdst, err := get_pod_info(dst) // destination (right)
	if err != nil {
		log.Fatalf("error: parsing file dst spec: %v", err)
	}

	xor := left != right
	if !xor {
		fmt.Println("cp error: both operands specify the location!")
		os.Exit(1)
	}

	if left { //  REMOTE -> LOCAL (rdst)
		newDest := false

		source, err := resolveDestination(lPod, lsrc)
		if err != nil {
			log.Fatalf("error: resolvingDestination: %v", err)
		}
		if source == "nonexistent" || source == "other" {
			log.Fatalf("No such file or directory: %s", lsrc)
		}

		info, err := os.Stat(rdst)
		if err != nil {
			if os.IsNotExist(err) {
				newDest = true
				fmt.Println("new destination could dir or file")
			} else {
				log.Fatal(err)
			}
		}

		args := []string{"exec", lPod}
		if lNS != "" {
			args = append(args, "-n")
			args = append(args, lNS)
		}

		if cliPrivateFile != "" {
			args = append(args, "--privkey")
			args = append(args, cliPrivateFile)
		}

		if cliPubKeyCertFile != "" {
			args = append(args, "--pubkeycert")
			args = append(args, cliPubKeyCertFile)
		}

		args = append(args, "--")

		src_dir := filepath.Dir(lsrc)
		src_base := filepath.Base(lsrc)

		args = append(args, "tar")
		args = append(args, "-C")

		if source == "file" { // copy file
			// Not writing the file to a directory
			if !newDest {
				if info.IsDir() {
					log.Fatalf("error: %s is a directory", rdst)
				}
			}
			// ccop exec lPod -- tar -C src_dir -cf - src_base | tar -xf - --to-stdout > rdst
			args = append(args, src_dir)
			args = append(args, "-cf")
			args = append(args, "-")
			args = append(args, src_base)

			secondCmd = []string{"-xf"}
			secondCmd = append(secondCmd, "-")
			secondCmd = append(secondCmd, "--to-stdout")

		} else { // copy directory
			// Not writing to file, but creating a directory
			if !newDest {
				if !info.IsDir() {
					log.Fatalf("error: %s is a file", rdst)
				}
			} else {
				// Create directory
				err := os.MkdirAll(rdst, 0750)
				if err != nil {
					log.Fatal(err)
				}
			}

			// ccop exec lPod -- tar -C lsrc - . | tar -xf - -C rdst
			args = append(args, lsrc)
			args = append(args, "-cf")
			args = append(args, "-")
			args = append(args, ".")

			secondCmd = []string{"-xf"}
			secondCmd = append(secondCmd, "-")
			secondCmd = append(secondCmd, "-C")
			secondCmd = append(secondCmd, rdst)

		}

		if cliDisplay {
			fmt.Println("=============== External Command ==============")
			fmt.Println("c1: ccop", strings.Join(args, " "), " | ")

			fmt.Println("c2: tar", strings.Join(secondCmd, " "))
			if source == "file" {
				fmt.Println("Re-directing c2's stdout to: ", rdst)
			}
			fmt.Println("===============================================")
		}

		if cliDry {
			return
		}

		if source == "file" { // copy file

			// Write out file
			outputFile, err := os.Create(rdst) // #nosec G304 -- destination path validated by caller
			if err != nil {
				log.Fatal("error: ", err)
			}

			c1 = exec.Command("ccop", args...) // #nosec G204 -- fixed binary name; args come from validated CLI flags
			c1.Stderr = os.Stderr              // surface child diagnostics on the terminal

			c2 = exec.Command("tar", secondCmd...) // #nosec G204 -- fixed binary name; args come from validated CLI flags

			c2.Stdout = outputFile
			defer outputFile.Close()

		} else {
			c1 = exec.Command("ccop", args...)     // #nosec G204
			c2 = exec.Command("tar", secondCmd...) // #nosec G204
			c2.Stdout = os.Stdout
		}

	} else { // LOCAL (lsrc) -> REMOTE (rdst)
		var randomStr string
		randomStr = ""

		destination, err := resolveDestination(rPod, rdst)
		if err != nil {
			log.Fatalf("error: resolvingDestination: %v", err)
		}

		info, err := os.Stat(lsrc)

		if os.IsNotExist(err) {
			log.Fatal(err)
		}

		if err != nil {
			log.Fatal(err)
		}

		// build the container command
		args = []string{"exec", rPod}
		args = append(args, "-i")

		if rNS != "" {
			args = append(args, "-n")
			args = append(args, rNS)
		}

		if cliContainerName != "" {
			args = append(args, "-c")
			args = append(args, cliContainerName)
		}

		if cliPrivateFile != "" {
			args = append(args, "--privkey")
			args = append(args, cliPrivateFile)
		}

		if cliPubKeyCertFile != "" {
			args = append(args, "--pubkeycert")
			args = append(args, cliPubKeyCertFile)
		}
		args = append(args, "--")

		// Build the first command, stream using tar
		firstCmd = []string{"cf"}
		firstCmd = append(firstCmd, "-")

		if info.IsDir() {
			// Src is directory so adjust streaming based on destination
			srcArgs, err := getSrcDirCopy(destination, lsrc)
			if err != nil {
				log.Fatal(err)
			}
			firstCmd = append(firstCmd, srcArgs...)

		} else { // File
			var srcArgs []string

			srcArgs, randomStr, err = getSrcFileCopy(destination, lsrc)
			if err != nil {
				log.Fatal(err)
			}
			firstCmd = append(firstCmd, srcArgs...)
		}

		// Build the second command based on whether input src is a file or directory
		if info.IsDir() { // Copy directory
			_ = randomStr

			if destination == "directory" {
				args = append(args, "tar")
				args = append(args, "xf")
				args = append(args, "-")
				args = append(args, "-C")
				args = append(args, rdst)

			} else {
				args = append(args, "sh")
				args = append(args, "-c")
				cmdStr = "mkdir -p " + "$1" + " && tar xf - -C " + "$1"
				args = append(args, cmdStr)
				args = append(args, "sh")
				args = append(args, rdst)

			}

			if cliDisplay {
				fmt.Println("=============== External Command ==============")
				fmt.Println("c1: tar", strings.Join(firstCmd, " "), "|")
				fmt.Println("c2: ccop", strings.Join(args, " "))
				fmt.Println("===============================================")

			}

			if cliDry {
				return
			}

			c1 = exec.Command("tar", firstCmd...) // #nosec G204 -- fixed binary name
			c2 = exec.Command("ccop", args...)    // #nosec G204 -- fixed binary name

		} else { // Copy file
			destArgs, err := getDestFileCopy(destination, rdst, randomStr)
			if err != nil {
				log.Fatal(err)
			}

			args = append(args, destArgs...)
			// file | nonexiting

			if cliDisplay {
				fmt.Println("=============== External Command ==============")
				fmt.Println("c1: tar", strings.Join(firstCmd, " "), "|")

				fmt.Println("c2: ccop", strings.Join(args, " "))
				fmt.Println("===============================================")
			}

			if cliDry {
				return
			}

			c1 = exec.Command("tar", firstCmd...) // #nosec G204 -- fixed binary name
			c2 = exec.Command("ccop", args...)    // #nosec G204 -- fixed binary name
		}

		// Connect c2 output to terminal
		c2.Stdout = os.Stdout

	}
	// Connect c1 output to c2 using raw OS pipes.
	// Using c1.StdoutPipe() (a Go-managed pipe) would cause the write-end to
	// stay open until c1.Wait() is called. For large transfers this creates a
	// deadlock: the pipe buffer fills, c1 blocks writing, c2 stalls reading,
	// and c1.Wait() is never reached. Raw pipes let us close the write-end
	// immediately after c1.Start() so c2 sees EOF as soon as c1 exits.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		log.Fatalf("error: creating pipe: %v", err)
	}
	c1.Stdout = pipeW
	c2.Stdin = pipeR

	// Start first command
	if err = c1.Start(); err != nil {
		log.Fatalf("error: can't start the c1, first command: %v", err)
	}
	// Close the write-end in the parent; the child (c1) owns it now.
	// Without this, c2 would never see EOF even after c1 exits.
	_ = pipeW.Close() // #nosec G104

	c2.Stderr = &stderr

	// Run second command
	if err = c2.Run(); err != nil {
		c1err := c1.Wait()
		log.Fatalf("error: can't run c2: %v stderr: %q  (c1 exit: %v)",
			err, stderr.String(), c1err)
	}
	_ = pipeR.Close() // #nosec G104

	if err = c1.Wait(); err != nil {
		fmt.Printf("error: c1 wait: %v\n", err)
	}
}

func get_pod_info(inputStr string) (bool, string, string, string, error) {
	flag := false
	ns := ""
	podName := ""
	fileSpec := ""

	if !strings.Contains(inputStr, ":") {
		return flag, ns, podName, inputStr, nil
	}

	partL, partR, err := splitInTwo(inputStr, ":")
	if err != nil {
		log.Fatalf("error: parsing : %v", err)

	}
	fileSpec = partR

	if strings.Contains(partL, "/") {

		subL, subR, err := splitInTwo(partL, "/")
		if err != nil {
			log.Fatalf("error: parsing /  %v", err)
		}
		return true, subL, subR, fileSpec, nil

	} else {
		return true, ns, partL, fileSpec, nil

	}
}

func splitInTwo(inputStr string, separator string) (string, string, error) {
	parts := strings.SplitN(inputStr, separator, 2)
	if len(parts) < 2 {
		return "", "", errors.New("not enough args")
	} else {
		if strings.Contains(parts[1], separator) {
			return "", "", errors.New("more than two args")
		} else { // exactls  part 2
			return parts[0], parts[1], nil

		}
	}

}

func resolveDestination(podName string, dest string) (string, error) {
	args := []string{"exec", podName}

	if cliContainerName != "" {
		args = append(args, "-c")
		args = append(args, cliContainerName)
	}

	if cliPrivateFile != "" {
		args = append(args, "--privkey")
		args = append(args, cliPrivateFile)
	}

	if cliPubKeyCertFile != "" {
		args = append(args, "--pubkeycert")
		args = append(args, cliPubKeyCertFile)
	}
	args = append(args, "--")
	args = append(args, "sh")
	args = append(args, "-c")
	args = append(args, resolveDestinationScript)
	args = append(args, "sh")
	args = append(args, dest)

	cmd := exec.Command("ccop", args...) // #nosec G204 -- fixed binary name

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve remote destination: %w", err)
	}

	result := strings.TrimSpace(string(output))

	switch result {
	case "directory", "file", "other", "nonexistent":
		return result, nil
	default:
		return "", fmt.Errorf("unexpected destination type: %q", result)
	}
}

func getSrcDirCopy(destination string, src string) ([]string, error) {
	var args []string

	base := filepath.Base(src)
	dir := filepath.Dir(src)

	switch destination {

	case "directory":
		if dir == "." {
			args = append(args, src)
		} else {
			args = append(args, "-C")
			args = append(args, dir)
			args = append(args, base)

		}
	case "nonexistent":
		args = append(args, "-C")
		args = append(args, src)
		args = append(args, ".")
	case "file":
		return nil, fmt.Errorf("destination is an existing file: %q", destination)
	default:
		return nil, fmt.Errorf("unsupported destination type: %q", destination)
	}
	return args, nil
}

func getSrcFileCopy(destination string, src string) ([]string, string, error) {
	var args []string
	var randomStr string
	var destFilename string

	base := filepath.Base(src)
	dir := filepath.Dir(src)

	switch destination {

	case "directory":
		if dir != "." {
			args = append(args, "-C")
			args = append(args, dir)
		}
		args = append(args, base)

	case "file", "nonexistent":
		randomNum := rand.IntN(32768) // #nosec G404 -- used only for temp filename collision avoidance, not security
		randomStr = strconv.Itoa(randomNum)
		destFilename = randomStr + "_" + base

		if dir != "." {
			args = append(args, "-C")
			args = append(args, dir)
		}
		args = append(args, base)
		text := "--transform=s|^" + base + "|" + destFilename + "|"
		args = append(args, text)

	default:
		return nil, "", fmt.Errorf("unsupported destination type: %q", destination)
	}
	return args, destFilename, nil
}

func getDestFileCopy(destination string, remoteDest string, srcBase string) ([]string, error) {
	var args []string

	dir := filepath.Dir(remoteDest)

	switch destination {

	case "directory":
		args = append(args, "tar")
		args = append(args, "xf")
		args = append(args, "-")
		args = append(args, "-C")
		args = append(args, remoteDest)
	case "file", "nonexistent":
		args = append(args, "sh")
		args = append(args, "-c")
		cmdStr := "mkdir -p " + "$1" + " && tar xf - -C " + "$1" + " && mv -f " + "$1/$2" + " " + "$3"
		args = append(args, cmdStr)
		args = append(args, "sh")
		args = append(args, dir)
		args = append(args, srcBase)
		args = append(args, remoteDest)

	default:
		return nil, fmt.Errorf("unsupported destination type: %q", destination)
	}
	return args, nil
}
