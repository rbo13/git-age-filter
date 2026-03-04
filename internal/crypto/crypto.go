package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

var (
	ErrNoRecipients = errors.New("at least one recipient is required")
	ErrNoIdentities = errors.New("at least one identity path is required")
	ErrNonLocalPath = errors.New("identity path must be a local filesystem path")
)

type EncryptOptions struct {
	Recipients []string
	Armored    bool
}

type DecryptOptions struct {
	IdentityPaths []string
}

func Encrypt(in io.Reader, out io.Writer, opts EncryptOptions) error {
	if len(opts.Recipients) == 0 {
		return ErrNoRecipients
	}

	recipients := make([]age.Recipient, 0, len(opts.Recipients))
	for _, raw := range opts.Recipients {
		recipient, err := ParseRecipient(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("parse recipient: %w", err)
		}
		recipients = append(recipients, recipient)
	}

	var (
		targetWriter io.Writer = out
		armorWriter  io.WriteCloser
		err          error
	)

	if opts.Armored {
		armorWriter = armor.NewWriter(out)
		targetWriter = armorWriter
	}

	encryptWriter, err := age.Encrypt(targetWriter, recipients...)
	if err != nil {
		if armorWriter != nil {
			_ = armorWriter.Close()
		}
		return fmt.Errorf("create encrypt writer: %w", err)
	}

	if _, err := io.Copy(encryptWriter, in); err != nil {
		_ = encryptWriter.Close()
		if armorWriter != nil {
			_ = armorWriter.Close()
		}
		return fmt.Errorf("encrypt data: %w", err)
	}

	if err := encryptWriter.Close(); err != nil {
		if armorWriter != nil {
			_ = armorWriter.Close()
		}
		return fmt.Errorf("finalize encryption: %w", err)
	}

	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return fmt.Errorf("finalize armor: %w", err)
		}
	}

	return nil
}

func Decrypt(in io.Reader, out io.Writer, opts DecryptOptions) error {
	if len(opts.IdentityPaths) == 0 {
		return ErrNoIdentities
	}

	identities, err := ParseIdentities(opts.IdentityPaths)
	if err != nil {
		return err
	}

	inputBytes, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read encrypted input: %w", err)
	}

	reader := bytes.NewReader(inputBytes)
	var decryptInput io.Reader = reader
	if IsArmored(inputBytes) {
		decryptInput = armor.NewReader(reader)
	}

	decryptReader, err := age.Decrypt(decryptInput, identities...)
	if err != nil {
		return fmt.Errorf("create decrypt reader: %w", err)
	}

	if _, err := io.Copy(out, decryptReader); err != nil {
		return fmt.Errorf("decrypt data: %w", err)
	}

	return nil
}

func IsArmored(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return bytes.HasPrefix(trimmed, []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

func IsCiphertext(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return bytes.HasPrefix(trimmed, []byte("age-encryption.org/v1")) || IsArmored(trimmed)
}

func ParseIdentities(paths []string) ([]age.Identity, error) {
	identities := make([]age.Identity, 0, len(paths))
	for _, rawPath := range paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}

		expanded, err := ExpandHome(path)
		if err != nil {
			return nil, fmt.Errorf("expand identity path %q: %w", path, err)
		}
		if !IsLocalPath(expanded) {
			return nil, fmt.Errorf("%w: %q", ErrNonLocalPath, path)
		}

		file, err := os.Open(expanded)
		if err != nil {
			return nil, fmt.Errorf("open identity file %q: %w", expanded, err)
		}

		parsed, err := age.ParseIdentities(bufio.NewReader(file))
		closeErr := file.Close()
		if err != nil {
			return nil, fmt.Errorf("parse identities from %q: %w", expanded, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close identity file %q: %w", expanded, closeErr)
		}

		identities = append(identities, parsed...)
	}

	if len(identities) == 0 {
		return nil, ErrNoIdentities
	}
	return identities, nil
}

func ParseRecipient(s string) (age.Recipient, error) {
	if recipient, err := age.ParseX25519Recipient(s); err == nil {
		return recipient, nil
	}
	if recipient, err := agessh.ParseRecipient(s); err == nil {
		return recipient, nil
	}
	return nil, fmt.Errorf("unsupported recipient format")
}

func ExpandHome(path string) (string, error) {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return home, nil
	}

	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}

	return path, nil
}

func IsLocalPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "age-plugin:") {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Scheme != "" {
		return false
	}
	return true
}
