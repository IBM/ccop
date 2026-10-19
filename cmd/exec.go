//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
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

// ttyExitError is returned by interactiveTty when the remote shell exits with
// a non-zero code.  The code is extracted from kubectl's plain-text
// "command terminated with exit code N" message so the caller can propagate it.
type ttyExitError struct{ code int }

func (e *ttyExitError) Error() string {
	return fmt.Sprintf("command terminated with exit code %d", e.code)
}

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
			var ttyErr *ttyExitError
			if errors.As(err, &ttyErr) {
				// Print the message (kubectl already printed it to the terminal
				// but we want it on stderr for scripting), then mirror the
				// remote exit code so the caller can detect it.
				fmt.Fprintf(os.Stderr, "%s\n", ttyErr.Error())
				os.Exit(ttyErr.code)
			}
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
			//
			//  Output frame adds header, nonce, and tag overhead, around 36 bytes, so
			//  read up to 4060 bytes because the output frame is 4096 bytes
			//
			buf := make([]byte, 4060)
			var seq uint32 = 1

			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					if seq == 0xFFFFFFFF {
						reportErr(fmt.Errorf("stdin: seq overflow"))
						return
					}

					// header = length(4B BE) | seq(4B BE), used as AAD.
					// length = nonce(12) + len(plaintext) + tag(16)
					payloadLen := uint32(gcm.NonceSize() + n + gcm.Overhead()) // #nosec G115 -- always < 12+4064+16
					var header [8]byte
					binary.BigEndian.PutUint32(header[:4], payloadLen)
					binary.BigEndian.PutUint32(header[4:], seq)

					// nonce = random(8B) | seq(4B BE)
					nonce := util.GenerateRandomBytes(gcm.NonceSize())
					binary.BigEndian.PutUint32(nonce[8:], seq)
					seq++

					ciphertext := gcm.Seal(nil, nonce, buf[:n], header[:])

					// wire: header(8) | nonce(12) | ciphertext+tag
					if err := writeFull(stdinPipe, header[:]); err != nil {
						reportErr(fmt.Errorf("stdin: write header: %v", err))
						return
					}
					if err := writeFull(stdinPipe, nonce); err != nil {
						reportErr(fmt.Errorf("stdin: write nonce: %v", err))
						return
					}
					if err := writeFull(stdinPipe, ciphertext); err != nil {
						reportErr(fmt.Errorf("stdin: write ciphertext: %v", err))
						return
					}
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					reportErr(fmt.Errorf("stdin: read: %v", err))
					return
				}
			}
		}()
	}

	go func() {
		defer stdoutPipe.Close()

		// sendDone signals the main goroutine: nil = clean drain, non-nil = aborted.
		// We send exactly once; the channel is buffered so this never blocks.
		sendDone := func(err error) { stdoutDone <- err }

		var hdr [4]byte
		reader := bufio.NewReaderSize(stdoutPipe, 65536)
		var lastSeq uint32 = 0

		for {
			_, err := io.ReadFull(reader, hdr[:])
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				sendDone(nil) // clean end of stream
				return
			}
			if err != nil {
				sendDone(fmt.Errorf("stdout: header read: %w", err))
				return
			}

			if bytes.Equal(hdr[:], magic[:]) {
				// Read the 8-byte frame header: length(4B) | seq(4B).
				var frameHdr [8]byte
				_, err = io.ReadFull(reader, frameHdr[:])
				if err != nil {
					sendDone(fmt.Errorf("stdout: frame header read: %w", err))
					return
				}

				length := binary.BigEndian.Uint32(frameHdr[:4])
				seq := binary.BigEndian.Uint32(frameHdr[4:])

				// Replay / reorder detection (pre-crypto).
				if seq <= lastSeq {
					sendDone(fmt.Errorf("stdout: replay/reorder seq=%d last=%d", seq, lastSeq))
					return
				}

				payload := make([]byte, length)
				_, err = io.ReadFull(reader, payload)
				if err != nil {
					sendDone(fmt.Errorf("stdout: payload read (seq=%d, length=%d): %w", seq, length, err))
					return
				}

				nonce := payload[:12]

				// Cross-check: nonce[8:12] must match header seq.
				if binary.BigEndian.Uint32(nonce[8:]) != seq {
					sendDone(fmt.Errorf("stdout: nonce/seq mismatch seq=%d nonce_seq=%d", seq, binary.BigEndian.Uint32(nonce[8:])))
					return
				}
				lastSeq = seq

				ciphertextTag := payload[12:]
				plaintext, err := gcm_stdout.Open(nil, nonce, ciphertextTag, frameHdr[:])
				if err != nil {
					sendDone(fmt.Errorf("stdout: decrypt (seq=%d): %w", seq, err))
					return
				}

				if _, werr := os.Stdout.Write(plaintext); werr != nil {
					sendDone(fmt.Errorf("stdout: write (seq=%d): %w", seq, werr))
					return
				}
			} else {
				line, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					sendDone(fmt.Errorf("stdout: non-magic line read: %w", err))
					return
				}
				msg := append(hdr[:], line...)
				if _, werr := os.Stdout.Write(msg); werr != nil {
					sendDone(fmt.Errorf("stdout: non-magic write: %w", werr))
					return
				}
			}
		}
	}()

	go func() {
		defer stderrPipe.Close()

		var hdr [4]byte
		reader := bufio.NewReader(stderrPipe)
		var lastSeq uint32 = 0
		for {
			_, err := io.ReadFull(reader, hdr[:])
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			if err != nil {
				reportErr(fmt.Errorf("stderr: header read: %v", err))
				return
			}

			if bytes.Equal(hdr[:], magic[:]) {
				// Read the 8-byte frame header: length(4B) | seq(4B).
				var frameHdr [8]byte
				_, err = io.ReadFull(reader, frameHdr[:])
				if err != nil {
					reportErr(fmt.Errorf("stderr: frame header read: %w", err))
					return
				}

				length := binary.BigEndian.Uint32(frameHdr[:4])
				seq := binary.BigEndian.Uint32(frameHdr[4:])

				// Replay / reorder detection (pre-crypto).
				if seq <= lastSeq {
					reportErr(fmt.Errorf("stderr: replay/reorder seq=%d last=%d", seq, lastSeq))
					return
				}

				payload := make([]byte, length)
				_, err = io.ReadFull(reader, payload)
				if err != nil {
					reportErr(fmt.Errorf("stderr: payload read (seq=%d, length=%d): %v", seq, length, err))
					return
				}

				nonce := payload[:12]

				// Cross-check: nonce[8:12] must match header seq.
				if binary.BigEndian.Uint32(nonce[8:]) != seq {
					reportErr(fmt.Errorf("stderr: nonce/seq mismatch seq=%d nonce_seq=%d", seq, binary.BigEndian.Uint32(nonce[8:])))
					return
				}
				//lastSeq = seq
				_ = seq

				ciphertextTag := payload[12:]
				plaintext, err := gcm_stderr.Open(nil, nonce, ciphertextTag, frameHdr[:])
				if err != nil {
					reportErr(fmt.Errorf("stderr: decrypt (seq=%d): %v", seq, err))
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
				msg := append(hdr[:], []byte(line)...)
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
		// Agent signaled done — all stdout frames are in the pipe.
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

// ttyGcmFrame encrypts plaintext into a single authenticated TTY record and
// writes it to w.
//
// Record wire format (mirrors AesGcmTtyProcessor on the agent side):
//
//	header   = length(4B BE) || seq(4B BE)   — 8 bytes, used as AAD
//	nonce    = random(8B) || seq(4B BE)      — 12 bytes
//	frame    = header(8B) || nonce(12B) || ciphertext+tag
//
// length = nonce(12) + len(plaintext) + tag(16).
func ttyGcmFrame(w io.Writer, gcm cipher.AEAD, seq uint32, plaintext []byte) error {
	payloadLen := uint32(gcm.NonceSize() + len(plaintext) + gcm.Overhead()) // #nosec G115 payloadLen is always < 12 + 4096 + 16

	// Build header (AAD).
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], payloadLen)
	binary.BigEndian.PutUint32(header[4:], seq)

	// Build nonce: 8 random bytes || seq (4B BE).
	nonce := util.GenerateRandomBytes(gcm.NonceSize())
	binary.BigEndian.PutUint32(nonce[8:], seq)

	ciphertext := gcm.Seal(nil, nonce, plaintext, header[:])

	// Write: header(8) || nonce(12) || ciphertext+tag.
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	if err := writeFull(w, nonce); err != nil {
		return err
	}
	return writeFull(w, ciphertext)
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

	if cliDry {
		return nil
	}

	cmd := exec.Command("kubectl", args...) // #nosec G204 -- fixed binary name

	// Put terminal in raw mode to prevent local echo.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pty: %v", err)
	}
	defer ptmx.Close()

	// TTY mode uses AES-GCM with per-record framing so every keystroke and
	// every output chunk is integrity-protected.
	//
	// Frame format (both directions):
	//   header(8B: length 4B + seq 4B) || nonce(12B) || ciphertext+tag
	//
	// The header is the AAD for AES-GCM; any tampering with length or the
	// sequence number is detected by the authentication tag.
	// The sequence number in the nonce and header must match; the receiver
	// enforces strict monotonic ordering to detect replays and reordering.

	// gcmEnc encrypts stdin→ptmx (client→agent direction).
	gcmEnc, err := util.AESGcmBlock(channelKeys.EncryptKey)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM encoder: %v", err)
	}

	// gcmDec decrypts ptmx→stdout (agent→client direction).
	gcmDec, err := util.AESGcmBlock(channelKeys.DecryptKey)
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM decoder: %v", err)
	}

	// done carries the outcome of the session: nil for clean exit, a
	// *ttyExitError when the remote shell exits with a non-zero code, or an
	// *exec.ExitError if kubectl itself fails.  Buffered with capacity 2 so
	// that both the PTY reader goroutine and the cmd.Wait() goroutine can
	// always send without blocking, avoiding a race where cmd.Wait() wins
	// before the PTY reader has parsed the "command terminated" line.
	done := make(chan error, 2)

	// Captures the first fatal crypto/framing error from any goroutine.
	errCh := make(chan error, 1)

	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	// stdin goroutine — encrypt each available chunk into one AES-GCM frame.
	go func() {
		buf := make([]byte, 4064)
		var sendSeq uint32 = 1

		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if sendSeq == 0xFFFFFFFF {
					reportErr(fmt.Errorf("tty: send counter overflow"))
					return
				}
				if werr := ttyGcmFrame(ptmx, gcmEnc, sendSeq, buf[:n]); werr != nil {
					reportErr(fmt.Errorf("tty: encrypt stdin: %v", werr))
					return
				}
				sendSeq++
			}
			if err != nil {
				if err == io.EOF {
					return
				}
				reportErr(fmt.Errorf("tty: stdin read: %v", err))
				return
			}
		}
	}()

	// ptmx reader goroutine — reassemble and decrypt AES-GCM frames from the
	// agent.  The PTY layer may split a single frame across multiple reads, so
	// we keep a reassembly buffer and only process complete records.
	//
	// In TTY mode stdout and stderr are multiplexed through ptmx.  kubectl
	// injects plain-text session messages (e.g. "command terminated with exit
	// code N", "If you don't see a command prompt") directly onto the PTY
	// stream.  These arrive as raw bytes from ptmx.Read and must be checked
	// FIRST, before the bytes are handed to the frame reassembler.
	go func() {
		var reassembly []byte
		rawBuf := make([]byte, 65536)
		var recvSeq uint32 = 0

		for {
			n, readErr := ptmx.Read(rawBuf)
			if n > 0 {
				chunk := rawBuf[:n]

				// Check for plain-text kubectl session messages first.
				// KubectlMsg detects messages like "command terminated with
				// exit code N" or "If you don't see a command prompt".
				// When endSession is true we extract the exit code (if any)
				// and signal done, mirroring the non-TTY stderr behaviour.
				// When endSession is false it is informational — skip it.
				kubeMsg, endSession := util.KubectlMsg(chunk)
				if kubeMsg {
					if endSession {
						const prefix = "command terminated with exit code "
						lineStr := strings.TrimRight(string(chunk), "\r\n")
						if strings.HasPrefix(lineStr, prefix) {
							codeStr := strings.TrimPrefix(lineStr, prefix)
							if code, parseErr := strconv.Atoi(strings.TrimSpace(codeStr)); parseErr == nil {
								done <- &ttyExitError{code: code}
								return
							}
						}
						// Session-ending message without a parseable exit
						// code (e.g. "Error from server") — report it as an
						// error.
						reportErr(fmt.Errorf("tty stderr: %s", chunk))
					}
					// Informational message ("If you don't see a command
					// prompt") — discard and keep reading.
					continue
				}

				// Not a plain-text kubectl message: treat as an encrypted
				// frame fragment and append to the reassembly buffer.
				reassembly = append(reassembly, chunk...)

				// Drain all complete frames from the buffer.
				for {
					// Need at least 8 bytes for the header.
					if len(reassembly) < 8 {
						break
					}

					payloadLen := binary.BigEndian.Uint32(reassembly[:4])
					seq := binary.BigEndian.Uint32(reassembly[4:8])

					// Sanity-check the header looks like a real frame.
					if payloadLen < 28 {
						reportErr(fmt.Errorf("tty: invalid frame header: payloadLen=%d seq=%d", payloadLen, seq))
						return
					}

					// Wait until the full frame body has arrived.
					totalFrame := 8 + int(payloadLen)
					if len(reassembly) < totalFrame {
						break
					}

					header := reassembly[:8]
					body := reassembly[8:totalFrame]
					reassembly = reassembly[totalFrame:]

					// Validate sequence number (strict monotonic).
					if seq <= recvSeq {
						reportErr(fmt.Errorf("tty: replay/reorder seq=%d, last=%d", seq, recvSeq))
						return
					}

					// body = nonce(12) || ciphertext+tag
					if len(body) < gcmDec.NonceSize() {
						reportErr(fmt.Errorf("tty: frame body too short: %d bytes", len(body)))
						return
					}
					nonce := body[:gcmDec.NonceSize()]
					ciphertextTag := body[gcmDec.NonceSize():]

					// Verify the seq embedded in the nonce matches the header.
					nonceSeq := binary.BigEndian.Uint32(nonce[8:])
					if nonceSeq != seq {
						reportErr(fmt.Errorf("tty: header seq %d != nonce seq %d", seq, nonceSeq))
						return
					}

					plaintext, derr := gcmDec.Open(nil, nonce, ciphertextTag, header)
					if derr != nil {
						reportErr(fmt.Errorf("tty: decrypt seq=%d: %v", seq, derr))
						return
					}

					recvSeq = seq

					if _, werr := os.Stdout.Write(plaintext); werr != nil {
						reportErr(fmt.Errorf("tty: stdout write: %v", werr))
						return
					}
				}
			}
			if readErr != nil {
				if errors.Is(readErr, syscall.EIO) || errors.Is(readErr, io.EOF) {
					done <- nil
				} else {
					reportErr(fmt.Errorf("tty: ptmx read: %v", readErr))
				}
				return
			}
		}
	}()

	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-errCh:
		_ = cmd.Process.Kill()
		return err

	case err := <-done:
		// Drain the second slot in case both the PTY reader and cmd.Wait()
		// fired at the same time.  If one of them is a *ttyExitError, that
		// takes precedence over a nil from cmd.Wait() so the caller gets the
		// remote exit code.
		var other error
		select {
		case other = <-done:
		default:
		}
		var ttyErr *ttyExitError
		if errors.As(err, &ttyErr) {
			return ttyErr
		}
		if errors.As(other, &ttyErr) {
			return ttyErr
		}
		// Neither slot carried a ttyExitError — return whichever is non-nil,
		// or nil if both are nil.
		if err != nil {
			return err
		}
		return other
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
