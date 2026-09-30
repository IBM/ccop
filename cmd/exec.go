//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	// "time"

	"github.com/cloudflare/circl/hpke"
	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/term"

	"ccop/util"
)

const payloadVerion = 1

type PayloadMessage struct {
	Type            string `msgpack:"type"` // Type "E" for ConfStruct
	Version         uint8  `msgpack:"version"`
	NameSpace       string `msgpack:"namespace"`
	PodName         string `msgpack:"podname"`
	ContainerName   string `msgpack:"containername"`
	TimeStamp       uint64 `msgpack:"timestamp"`
	EncapsulatedKey []byte `msgpack:"encapsulatedkey"` // When you writeout it is a string!
	Ciphertext      []byte `msgpack:"ciphertext"`
}

type Meta struct {
	Type string `msgpack:"type"`
}

// execCmd represents the exec command
var (
	cliContainerName  string
	cliDisplay        bool
	cliPodName        string
	cliPrivateFile    string
	cliPubKeyCertFile string
	cliNameSpace      string
	cliStdin          bool
	cliTty            bool
	cliDry            bool

	execCmd = &cobra.Command{
		Use:   "exec",
		Short: "Execute a command in a container",
		Long: `Execute a command in a container.

Examples:
  # Get output from running the 'date' command from pod mypod, using the first container by default
  ccop exec mypod -- date
  
  # Get output from running the 'date' command in ruby-container from pod mypod
  ccop exec mypod -c ruby-container -- date
  
  # Switch to raw terminal mode; sends stdin to 'bash' in ruby-container from pod mypod
  # and sends stdout/stderr from 'bash' back to the client
  ccop exec mypod -c ruby-container -i -t -- bash -il
  
  # List contents of /usr from the first container of pod mypod and sort by modification time
  # If the command you want to execute in the pod has any flags in common (e.g. -i),
  # you must use two dashes (--) to separate your command's flags/arguments
  # Also note, do not surround your command and its flags/arguments with quotes
  # unless that is how you would execute it normally (i.e., do ls -t /usr, not "ls -t /usr")
  ccop exec mypod -i -t -- ls -t /usr
  
  # Get output from running 'date' command from the first pod of the deployment mydeployment, using
the first container by default
  ccop exec deploy/mydeployment -- date
  
  # Get output from running 'date' command from the first pod of the service myservice, using the
first container by default
  ccop exec svc/myservice -- date
`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 2 {
				fmt.Println("error: pod, type/name or --filename must be specified")
				fmt.Println("usage: exec POD [flags] -- COMMAND")
				os.Exit(1)
			}

			//processCmdExec(args)
			cliPodName = args[0] // removes the need for -p flag

			if err := util.CheckCCOPEnabled(cliNameSpace, cliPodName, ""); err != nil {
				log.Fatalf("error: %v", err)
			}
			containerCmd := args[1:]
			processCmdExec(containerCmd)
			//fmt.Println("=== PROGRAM EXITING ===")
		},
	}
)

func init() {
	rootCmd.AddCommand(execCmd)
	execCmd.PersistentFlags().StringVar(&cliPrivateFile, "privkey", "", "(Optional) User private key file (PEM) for HPKE authenticated encryption")
	execCmd.PersistentFlags().StringVar(&cliPubKeyCertFile, "pubkeycert", "", "(Optional) Agent public key certificate file (PEM) for HPKE authenticated encryption")
	execCmd.PersistentFlags().StringVarP(&cliContainerName, "container", "c", "", "Container name or ID")
	execCmd.PersistentFlags().StringVarP(&cliNameSpace, "namespace", "n", "default", "Namespace scope")
	execCmd.PersistentFlags().BoolVarP(&cliStdin, "stdin", "i", false, "Pass stdin to the container")
	execCmd.PersistentFlags().BoolVarP(&cliTty, "tty", "t", false, "Stdin is a TTY")
	execCmd.PersistentFlags().BoolVarP(&cliDisplay, "display", "d", false, "Display kubectl command line")
	execCmd.PersistentFlags().BoolVarP(&cliDry, "dryrun", "", false, "Dry run doesn't invoke kubectl")

}

func processCmdExec(cmdargs []string) {
	var packedPayload []byte
	//var opaqueItem OpaqueStruct
	var sealer hpke.Sealer
	var err error

	userPrivateKeyFile, err := util.GetdUserPrivKeyFile(cliPrivateFile)
	if err != nil {
		log.Fatalf(`error: %v 
Please either:
  - specify a key file with --pubkeycert <keyfile>, or
  - run "config -c" first to set key file paths.`, err)
	}

	recvPubKeyFile, err := util.GetRecvPubKeyFile(cliPubKeyCertFile, cliNameSpace, cliPodName)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if !cliStdin && !cliTty {
		//fmt.Println("no -i or -t option")
		packedPayload, sealer, err = getHPKEPayload(cmdargs, userPrivateKeyFile, recvPubKeyFile)

	} else if cliStdin && !cliTty {
		//fmt.Println("-i and no -t options")
		packedPayload, sealer, err = getHPKEPayload(cmdargs, userPrivateKeyFile, recvPubKeyFile)
		//packedPayload, opaqueItem, err = getConfPayload(cmdargs)

	} else if cliStdin && cliTty {
		//fmt.Println("-i and -t options")
		packedPayload, sealer, err = getHPKEPayload(cmdargs, userPrivateKeyFile, recvPubKeyFile)
		//packedPayload, opaqueItem, err = getConfPayload(cmdargs)

	} else {
		// packedPayload, err = getAuthPayload(cmdargs)
		log.Fatalf("error: tty option requires -i")

	}

	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if cliDisplay {
		displayPacked(packedPayload)
	}

	payloadB64 := base64.StdEncoding.EncodeToString(packedPayload)

	if cliTty {
		if err = interactiveTty(payloadB64, sealer); err != nil {
			log.Fatalf("error: %v ", err)
		}
	} else {
		//if err = interactive(payloadB64, sigB64, opaqueItem); err != nil {
		if err = interactive(payloadB64, sealer); err != nil {
			log.Fatalf("error: %v ", err)
		}

	}

}
/*
func processInput(chunk []byte) []byte {
	return chunk
}

func processOutput(chunk []byte) []byte {
	return chunk
}
*/

func interactive(payloadB64 string, sealer hpke.Sealer) error {
	var cmd *exec.Cmd
	var channelKeys *util.ChannelKeys
	var magic = [4]byte{0xD1, 0xA2, 0xE3, 0xB4}

	args := []string{"exec", cliPodName}

	if cliContainerName != "" {
		args = append(args, "-c")
		args = append(args, cliContainerName)
	}

	if cliStdin {
		args = append(args, "-i")
	}

	args = append(args, "--")
	args = append(args, "--payload")
	args = append(args, payloadB64)

	if cliDisplay {
		fmt.Println("=============== External Command ==============")
		fmt.Println("kubectl", strings.Join(args, " "))
		fmt.Println("===============================================")

	}

	channelKeys, err := util.DeriveChannelKeys(sealer)
	if err != nil {
		return fmt.Errorf("failed to derive channel keys: %v", err)
	}

	if cliDisplay {
		//	fmt.Printf(" keys to prints %+v\n", channelKeys)
	}

	if cliDry {
		return nil
	}

	cmd = exec.Command("kubectl", args...) // #nosec G204 -- fixed binary name

	// Use raw OS pipes so cmd.Wait() does not manage pipe lifetime.
	// With cmd.StdoutPipe(), cmd.Wait() blocks until the pipe is drained,
	// creating a deadlock with our goroutine. With a raw pipe we control
	// when each end closes independently.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating stderr pipe: %v", err)
	}

	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	// Aliases used by the goroutines below (read ends for stdout/stderr,
	// write end for stdin).
	stdinPipe := stdinW
	stdoutPipe := stdoutR
	stderrPipe := stderrR

	// Key used for writing (stdin goroutine only — not shared).
	gcm, err := util.AESGcmBlock(channelKeys.EncryptKey)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM block cipher (encrypt): %v", err)
	}

	// Separate cipher.AEAD instances per goroutine that decrypts.
	// cipher.AEAD (AES-GCM) is NOT safe for concurrent use: the stdout and
	// stderr goroutines both call Open() and can run simultaneously when a
	// large file transfer causes pipeW to fill and block the stdout goroutine
	// while the agent sends the stderr completion frame.  Two calls to Open()
	// on the same instance corrupt each other's internal state.
	gcm_stdout, err := util.AESGcmBlock(channelKeys.DecryptKey)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM block cipher (stdout decrypt): %v", err)
	}
	gcm_stderr, err := util.AESGcmBlock(channelKeys.DecryptKey)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM block cipher (stderr decrypt): %v", err)
	}
	// Capture non-error exit
	done := make(chan error, 1)

	// Designed to capture the first error!
	errCh := make(chan error, 1)

	// Closed when the stdout goroutine has finished draining all output cleanly.
	// If the goroutine exits due to an error it sends that error here instead of
	// closing, so the select below can distinguish clean-drain from aborted-drain.
	stdoutDone := make(chan error, 1)

	// Closed by the stderr goroutine when the agent completion frame arrives.
	stderrGotCompletion := make(chan struct{})

	// Helper to report first error
	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	//
	// Concurrent processing of the pipes
	//
	if !cliStdin {
		// No stdin requested: close the pipe immediately so kubectl does not
		// wait for input and exits as soon as the command finishes.
		_ = stdinPipe.Close() // #nosec G104
	} else {
		go func() {
			defer stdinPipe.Close()

			// Final frame must be 4096 bytes, encrypting adds around 32 bytes
			buf := make([]byte, 4064)
			var counter uint32 = 1

			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {

					if counter == 0xFFFFFFFF {
						reportErr(fmt.Errorf("counter overflow: cannot encrypt more messages"))
					}

					plaintext := buf[:n]

					nonce := util.GenerateRandomBytes(gcm.NonceSize())

					// nonce [12] = nonce [8] + counter [4]
					binary.BigEndian.PutUint32(nonce[8:], counter)
					counter++

					ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
					// frame = nonce + [ciphertext + tag]
					framePayload := append(nonce, ciphertext...)

					var frameLen [4]byte
					binary.BigEndian.PutUint32(frameLen[:], uint32(len(framePayload))) // #nosec G115 -- framePayload is always < 4096 bytes

					if err := writeFull(stdinPipe, frameLen[:]); err != nil {
						reportErr(fmt.Errorf("writeFull len stdinPipe: %v", err))
					}

					if err := writeFull(stdinPipe, framePayload); err != nil {
						reportErr(fmt.Errorf("writeFull frame stdinPipe: %v", err))
					}

				}
				// Move up
				if err != nil {
					if err == io.EOF {
						break
					}
					reportErr(fmt.Errorf(" err %v: ", err))
				}
			}
		}()
	}

	go func() {
		defer stdoutPipe.Close()

		// sendDone signals the main goroutine: nil = clean drain, non-nil = aborted.
		// We send exactly once; the channel is buffered so this never blocks.
		sendDone := func(err error) { stdoutDone <- err }

		frame := make([]byte, 4)
		reader := bufio.NewReaderSize(stdoutPipe, 65536)
		var outputCounter uint32 = 0

		for {
			_, err := io.ReadFull(reader, frame)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				sendDone(nil) // clean end of stream
				return
			}
			if err != nil {
				sendDone(fmt.Errorf("stdout: header read: %w", err))
				return
			}

			if bytes.Equal(frame, magic[:]) {
				// Read the 4-byte length.
				_, err = io.ReadFull(reader, frame)
				if err != nil {
					sendDone(fmt.Errorf("stdout: length read: %w", err))
					return
				}

				length := binary.BigEndian.Uint32(frame)
				payload := make([]byte, length)

				_, err = io.ReadFull(reader, payload)
				if err != nil {
					sendDone(fmt.Errorf("stdout: payload read (counter=%d, length=%d): %w", outputCounter, length, err))
					return
				}

				nonce := payload[:12]

				// Replay detection
				counter := binary.BigEndian.Uint32(nonce[8:12])
				if counter <= outputCounter {
					sendDone(fmt.Errorf("stdout: replay detected counter=%d", counter))
					return
				}
				outputCounter = counter

				ciphertextTag := payload[12:]
				plaintext, err := gcm_stdout.Open(nil, nonce, ciphertextTag, nil)
				if err != nil {
					sendDone(fmt.Errorf("stdout: decrypt (counter=%d): %w", outputCounter, err))
					return
				}

				if _, werr := os.Stdout.Write(plaintext); werr != nil {
					sendDone(fmt.Errorf("stdout: write (counter=%d): %w", outputCounter, werr))
					return
				}
			} else {
				line, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					sendDone(fmt.Errorf("stdout: non-magic line read: %w", err))
					return
				}
				msg := append(frame, line...)
				if _, werr := os.Stdout.Write(msg); werr != nil {
					sendDone(fmt.Errorf("stdout: non-magic write: %w", werr))
					return
				}
			}
		}
	}()

	go func() {
		defer stderrPipe.Close()

		frame := make([]byte, 4)
		reader := bufio.NewReader(stderrPipe)
		for {
			_, err := io.ReadFull(reader, frame)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			if err != nil {
				reportErr(fmt.Errorf("failed to read stderr header: %v", err))
				return
			}

			if bytes.Equal(frame, magic[:]) {
				_, err = io.ReadFull(reader, frame)
				if err != nil {
					reportErr(fmt.Errorf("failed to read stderr length: %w", err))
					return
				}

				length := binary.BigEndian.Uint32(frame)
				payload := make([]byte, length)

				_, err = io.ReadFull(reader, payload)
				if err != nil {
					reportErr(fmt.Errorf("failed to read stderr payload: %v", err))
					return
				}

				nonce := payload[:12]
				ciphertextTag := payload[12:]
				plaintext, err := gcm_stderr.Open(nil, nonce, ciphertextTag, nil)
				if err != nil {
					reportErr(fmt.Errorf("stderr decrypt: %v", err))
					return
				}

				_, _ = os.Stderr.Write(plaintext) // #nosec G104
				// Signal that the agent completion frame arrived. The main
				// goroutine will drain stdout fully before killing kubectl.
				close(stderrGotCompletion)
				return
			} else {
				line, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					reportErr(fmt.Errorf("stderr: reading text message %v", err))
					return
				}
				msg := append(frame, []byte(line)...)
				// Plain-text kubectl stderr (e.g. warnings, informational messages).
				// Write it to our own stderr for visibility but do NOT treat it as a
				// fatal error — aborting the transfer here would truncate the stdout
				// stream and corrupt the copied file.  Only a magic completion/error
				// frame from the agent should decide the outcome of the session.
				fmt.Fprintf(os.Stderr, "kubectl stderr: %s", msg)
				// continue reading
			}
		}
	}()

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start cmd: %v", err)
	}

	// Close the write ends of stdout/stderr in the parent process now that
	// the child has inherited them. This ensures our goroutines see EOF when
	// the child exits, without waiting for cmd.Wait().
	_ = stdoutW.Close() // #nosec G104
	_ = stderrW.Close() // #nosec G104
	// Close the read end of stdin in the parent; the child owns it now.
	_ = stdinR.Close() // #nosec G104

	go func() {
		done <- cmd.Wait()
	}()

	// Wait for agent completion signal, an error, or kubectl exit.
	//
	// stdoutDone now carries the outcome of the stdout goroutine:
	//   nil  = goroutine drained all frames cleanly (clean EOF)
	//   err  = goroutine aborted mid-stream (read/write/decrypt error)
	//
	// We must always wait for stdoutDone before returning so the caller
	// knows all writes to os.Stdout are complete (or failed).
	waitStdout := func() error { return <-stdoutDone }

	select {
	case <-stderrGotCompletion:
		// Agent signalled done — all stdout frames are in the pipe.
		// Wait for the goroutine to drain them, then tidy up.
		drainErr := waitStdout()
		_ = cmd.Process.Kill()
		return drainErr

	case err := <-errCh:
		// A goroutine hit an error. Kill kubectl and wait for the stdout
		// goroutine to finish (it may have already sent on stdoutDone).
		_ = cmd.Process.Kill()
		_ = waitStdout() // drain result; the errCh error is the real one
		return err

	case err := <-done:
		// kubectl exited on its own; drain stdout before returning.
		drainErr := waitStdout()
		if err != nil {
			return err
		}
		return drainErr
	}
}

func interactiveTty(payloadB64 string, sealer hpke.Sealer) error {
	args := []string{"exec", cliPodName}
	var channelKeys *util.ChannelKeys

	if cliContainerName != "" {
		args = append(args, "-c")
		args = append(args, cliContainerName)
	}

	if cliStdin {
		args = append(args, "-i")
	}

	if cliTty {
		args = append(args, "-t")
	}

	args = append(args, "--")
	args = append(args, "--payload")
	args = append(args, payloadB64)

	if cliDisplay {
		fmt.Println("=============== External Command ==============")
		fmt.Println("kubectl", strings.Join(args, " "))
		fmt.Println("===============================================")

	}

	channelKeys, err := util.DeriveChannelKeys(sealer)
	if err != nil {
		return fmt.Errorf("failed to derive channel keys: %v", err)
	}

	if cliDisplay {
		//	fmt.Printf(" keys to prints %+v\n", channelKeys)
	}

	if cliDry {
		return nil
	}

	cmd := exec.Command("kubectl", args...) // #nosec G204 -- fixed binary name

	// Put terminal in raw mode to prevent local echo
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return (fmt.Errorf("failed to set raw mode: %v", err))
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return (fmt.Errorf("failed to start pty: %v", err))
	}
	defer ptmx.Close()

	// TTY mode uses AES-CTR (a stateful stream cipher) rather than AES-GCM (AEAD).
	//
	// Trade-off: confidentiality vs. per-frame integrity
	//   - Confidentiality is maintained: keys are derived from the HPKE exporter and
	//     are unique per session (fresh ephemeral KEM randomness in SetupAuth). The
	//     CTR counter advances automatically through the stream lifetime, so the IV
	//     is consumed exactly once.
	//   - Per-byte integrity is NOT provided: AES-CTR carries no authentication tag.
	//     A bit-flip in the ciphertext produces a predictable bit-flip in the
	//     plaintext (stream cipher malleability). There is also no sequence counter,
	//     so reordering or truncation by an intermediary is not detected at this layer.
	//
	// Rationale: an interactive TTY session is inherently low-latency and
	// character-at-a-time; framing every keystroke with an AEAD tag adds overhead
	// and complexity. The transport (kubectl SPDY/WebSocket) provides its own
	// ordering.
	decoder, err := util.AESCtrStream(channelKeys.DecryptKey, channelKeys.DecryptIV)
	if err != nil {
		return (fmt.Errorf("failed to create decoder: %v", err))
	}

	encoder, err := util.AESCtrStream(channelKeys.EncryptKey, channelKeys.EncryptIV)
	if err != nil {
		return (fmt.Errorf("failed to create encoder: %v", err))
	}

	// Capture non-error exit
	done := make(chan error, 1)

	// Designed to capture the first error!
	errCh := make(chan error, 1)

	// Helper to report first error
	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	go func() {
		buf := make([]byte, 4064)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				encoded := util.EncodeDecode(encoder, buf[:n])
				_, werr := ptmx.Write(encoded)
				if werr != nil {
					reportErr(fmt.Errorf("%v: ", werr))
				}
			}
			if err != nil {
				reportErr(fmt.Errorf("%v: ", err))
			}
		}
	}()

	go func() {
		buf := make([]byte, 4064)

		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				// In TTY mode stdout and stderr are multiplexed through ptmx.
				// KubectlMsg detects plain-text kubectl/server error messages
				// (e.g. "command terminated with exit code", "Error from server").
				// When endSession is true we report the error so that the select
				// below kills the process, mirroring the non-TTY stderr behaviour.
				// When endSession is false it is an informational message
				// (e.g. "If you don't see a command prompt") — just skip it.
				kubeMsg, endSession := util.KubectlMsg(buf[:n])
				if kubeMsg {
					if endSession {
						// done <- nil
						// Returns an error on an exit
						reportErr(fmt.Errorf("tty stderr: %s", buf[:n]))
					}
					continue
				}
				decoded := util.EncodeDecode(decoder, buf[:n])
				_, _ = os.Stdout.Write(decoded) // #nosec G104
			}
			// Must come after
			if err != nil {
				// Check if process has exited after read
				if errors.Is(err, syscall.EIO) || errors.Is(err, io.EOF) {
					done <- nil
				} else {
					reportErr(fmt.Errorf("XXX %v: ", err))
				}
			}
		}
	}()

	go func() {
		done <- cmd.Wait()
	}()

	// wait for either error OR command completion
	select {
	case err := <-errCh:
		// kill process on first goroutine error, cleaning up
		_ = cmd.Process.Kill()
		return err

	case err := <-done:
		// command finished normally
		return err
	}
}

func getHPKEPayload(cmdargs []string, senderPrivKeyFilename string, recvPubKeyFilename string) ([]byte, hpke.Sealer, error) {
	{

		var aad util.AAD
		var partyCtx *util.PartyContext

		aad.Version = payloadVerion
		aad.NameSpace = cliNameSpace
		aad.PodName = cliPodName
		aad.ContainerName = cliContainerName
		aad.Timestamp = util.GetTimeStamp()

		encoded_aad := util.EncodeAAD(aad)
		info := []byte("ccop->agent command v1")

		rpubkey, err := util.LoadP256PublicKeyFromCert(recvPubKeyFilename)
		if err != nil {
			return nil, nil, err
		}

		sprivkey, err := util.LoadP256PrivateKeyFromPEM(senderPrivKeyFilename)
		if err != nil {
			return nil, nil, err
		}
		cmdargsBytes, err := serializeCommandArgs(cmdargs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize command args: %w", err)
		}

		partyCtx, err = util.HPKEAuthEncryptWithContext(sprivkey, rpubkey, cmdargsBytes, encoded_aad, info)
		if err != nil {
			return nil, nil, err
		}

		item := PayloadMessage{Type: "C", Version: aad.Version, NameSpace: cliNameSpace, PodName: cliPodName, ContainerName: cliContainerName,
			TimeStamp: aad.Timestamp, EncapsulatedKey: partyCtx.Message.EncapsulatedKey, Ciphertext: partyCtx.Message.Ciphertext}

		payloadstruct, err := msgpack.Marshal(item)
		if err == nil {
			return payloadstruct, partyCtx.Sealer, nil
		} else {
			return nil, partyCtx.Sealer, err
		}

	}
}

func serializeCommandArgs(args []string) ([]byte, error) {
	return msgpack.Marshal(args)
}

// Deserialize (receiver side)
func deserializeCommandArgs(data []byte) ([]string, error) {
	var args []string
	err := msgpack.Unmarshal(data, &args)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal command args: %w", err)
	}
	return args, nil
}

func displayPacked(data []byte) {
	var v map[string]interface{}
	//fmt.Println(data)
	err := msgpack.Unmarshal(data, &v)
	if err != nil {
		panic(err)
	}

	pretty, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(pretty))
}

func writeFull(w io.Writer, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := w.Write(buf[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}
