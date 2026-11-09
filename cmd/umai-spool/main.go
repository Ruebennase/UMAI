// Command umai-spool provides a standalone producer CLI for publishing immutable
// messages into a UMAI spool directory without touching server-owned internal state.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}

	switch args[0] {
	case "publish":
		return runPublish(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "umai-spool: unknown subcommand %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: umai-spool <command> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  publish    Stage a complete message in <dataDir>/prepare/ and atomically publish it to <dataDir>/outbox/")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run 'umai-spool publish -h' for publish flags.")
}

func runPublish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dataDir        string
		msgID          string
		payloadStr     string
		payloadFile    string
		attachPaths    stringSliceFlag
		maxAttachBytes int64
		senderID       string
		receiverID     string
		signingKeyFile string
		signingKeyEnv  string
		allowUnsigned  bool
	)

	fs.StringVar(&dataDir, "data", "", "Path to the UMAI spool root directory (required)")
	fs.StringVar(&msgID, "id", "", "Explicit Message ID (auto-generated if omitted)")
	fs.StringVar(&payloadStr, "payload", "", "Inline JSON payload string (defaults to {})")
	fs.StringVar(&payloadFile, "payload-file", "", "Path to a JSON payload file")
	fs.Var(&attachPaths, "attach", "Path to an attachment file (repeatable)")
	fs.Int64Var(&maxAttachBytes, "max-attachment-bytes", 100*1024*1024, "Maximum size per attachment in bytes")
	fs.StringVar(&senderID, "sender", os.Getenv("UMAI_LOCAL_IDENTITY"), "Local sender identity (or UMAI_LOCAL_IDENTITY)")
	fs.StringVar(&receiverID, "receiver", os.Getenv("UMAI_PEER_IDENTITY"), "Intended peer receiver identity (or UMAI_PEER_IDENTITY)")
	fs.StringVar(&signingKeyFile, "signing-key-file", "", "Path to file containing hex-encoded Ed25519 private key")
	fs.StringVar(&signingKeyEnv, "signing-key-env", "UMAI_SIGNING_PRIVATE_KEY", "Environment variable containing hex-encoded Ed25519 private key")
	fs.BoolVar(&allowUnsigned, "unsigned", false, "Publish without an Ed25519 signature")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "umai-spool publish: unexpected positional arguments: %v\n", fs.Args())
		return 2
	}
	if strings.TrimSpace(dataDir) == "" {
		fmt.Fprintln(stderr, "umai-spool publish: -data <dir> is required")
		return 2
	}
	if payloadStr != "" && payloadFile != "" {
		fmt.Fprintln(stderr, "umai-spool publish: specify at most one of -payload or -payload-file")
		return 2
	}

	var payload any = map[string]any{}
	var rawPayload []byte
	if payloadFile != "" {
		b, err := os.ReadFile(payloadFile)
		if err != nil {
			fmt.Fprintf(stderr, "umai-spool publish: reading payload file: %v\n", err)
			return 1
		}
		rawPayload = b
	} else if payloadStr != "" {
		rawPayload = []byte(payloadStr)
	}
	if len(rawPayload) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawPayload))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			fmt.Fprintf(stderr, "umai-spool publish: invalid payload JSON: %v\n", err)
			return 2
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			fmt.Fprintln(stderr, "umai-spool publish: invalid payload JSON: trailing data")
			return 2
		}
	}

	var signing *umaispool.SigningConfig
	if !allowUnsigned {
		var privHex string
		if signingKeyFile != "" {
			b, err := os.ReadFile(signingKeyFile)
			if err != nil {
				fmt.Fprintf(stderr, "umai-spool publish: reading signing key file: %v\n", err)
				return 1
			}
			privHex = strings.TrimSpace(string(b))
		} else if signingKeyEnv != "" {
			privHex = strings.TrimSpace(os.Getenv(signingKeyEnv))
		}
		_, privKey, err := umaispool.ParsePrivateKey(privHex)
		if err != nil {
			fmt.Fprintf(stderr, "umai-spool publish: signing key error (set %s, pass -signing-key-file, or pass -unsigned): %v\n", signingKeyEnv, err)
			return 2
		}
		signing = &umaispool.SigningConfig{
			LocalIdentity: senderID,
			PeerIdentity:  receiverID,
			PrivateKey:    privKey,
		}
	}

	var openFiles []*os.File
	defer func() {
		for _, f := range openFiles {
			_ = f.Close()
		}
	}()

	attachments := make([]umaispool.AttachmentReader, 0, len(attachPaths))
	for _, p := range attachPaths {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintf(stderr, "umai-spool publish: opening attachment %q: %v\n", p, err)
			return 1
		}
		openFiles = append(openFiles, f)
		fi, err := f.Stat()
		if err != nil {
			fmt.Fprintf(stderr, "umai-spool publish: stating attachment %q: %v\n", p, err)
			return 1
		}
		if !fi.Mode().IsRegular() {
			fmt.Fprintf(stderr, "umai-spool publish: attachment %q must be a regular file\n", p)
			return 2
		}
		attachments = append(attachments, umaispool.AttachmentReader{
			Name:   filepath.Base(p),
			Reader: f,
		})
	}

	msg, err := umaispool.Publish(umaispool.PublishRequest{
		DataDir:           dataDir,
		ID:                msgID,
		Payload:           payload,
		Attachments:       attachments,
		MaxAttachmentSize: maxAttachBytes,
		Signing:           signing,
		AllowUnsigned:     allowUnsigned,
	})
	if err != nil {
		fmt.Fprintf(stderr, "umai-spool publish: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(msg); err != nil {
		fmt.Fprintf(stderr, "umai-spool publish: encoding output: %v\n", err)
		return 1
	}
	return 0
}
