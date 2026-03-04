package filter

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"github.com/rbo13/git-age-filter/internal/crypto"
	"github.com/rbo13/git-age-filter/internal/policy"
)

var (
	ErrRequiredPathNotEncrypted = fmt.Errorf("required protected path content is not age-encrypted")
	ErrFileTooLarge             = fmt.Errorf("input exceeds configured max_file_size")
)

type CleanRequest struct {
	Path            string
	Input           io.Reader
	Policy          *policy.File
	IndexBlobLookup func(path string) ([]byte, error)
}

type SmudgeRequest struct {
	Path   string
	Input  io.Reader
	Policy *policy.File
}

func Clean(req CleanRequest, out io.Writer) error {
	if req.Policy == nil {
		return fmt.Errorf("policy is required")
	}

	input, err := io.ReadAll(req.Input)
	if err != nil {
		return fmt.Errorf("read clean input: %w", err)
	}

	rule := req.Policy.Match(req.Path)
	if rule == nil || !rule.Required {
		_, err := out.Write(input)
		return err
	}

	if crypto.IsCiphertext(input) {
		_, err := out.Write(input)
		return err
	}

	if req.Policy.Defaults.MaxFileSize > 0 && int64(len(input)) > req.Policy.Defaults.MaxFileSize {
		return ErrFileTooLarge
	}

	indexBlobLookup := req.IndexBlobLookup
	if indexBlobLookup == nil {
		indexBlobLookup = readIndexBlob
	}

	if len(req.Policy.Identities) > 0 {
		existingCipher, err := indexBlobLookup(req.Path)
		if err == nil && crypto.IsCiphertext(existingCipher) {
			var existingPlain bytes.Buffer
			err = crypto.Decrypt(bytes.NewReader(existingCipher), &existingPlain, crypto.DecryptOptions{
				IdentityPaths: req.Policy.Identities,
			})
			if err == nil && bytes.Equal(existingPlain.Bytes(), input) {
				_, writeErr := out.Write(existingCipher)
				return writeErr
			}
		}
	}

	recipients, err := req.Policy.ResolvedRecipients(*rule)
	if err != nil {
		return fmt.Errorf("resolve recipients: %w", err)
	}

	armored := req.Policy.Defaults.Armored
	if rule.Armored != nil {
		armored = *rule.Armored
	}

	if err := crypto.Encrypt(bytes.NewReader(input), out, crypto.EncryptOptions{
		Recipients: recipients,
		Armored:    armored,
	}); err != nil {
		return fmt.Errorf("encrypt protected path %q: %w", req.Path, err)
	}

	return nil
}

func readIndexBlob(path string) ([]byte, error) {
	cmd := exec.Command("git", "show", ":"+path)
	return cmd.Output()
}

func Smudge(req SmudgeRequest, out io.Writer) error {
	if req.Policy == nil {
		return fmt.Errorf("policy is required")
	}

	input, err := io.ReadAll(req.Input)
	if err != nil {
		return fmt.Errorf("read smudge input: %w", err)
	}

	rule := req.Policy.Match(req.Path)
	if rule == nil {
		_, err := out.Write(input)
		return err
	}

	if !crypto.IsCiphertext(input) {
		if rule.Required {
			return ErrRequiredPathNotEncrypted
		}
		_, err := out.Write(input)
		return err
	}

	err = crypto.Decrypt(bytes.NewReader(input), out, crypto.DecryptOptions{
		IdentityPaths: req.Policy.Identities,
	})
	if err == nil {
		return nil
	}

	if req.Policy.Defaults.OnMissingIdentity == policy.OnMissingIdentityPass {
		_, writeErr := out.Write(input)
		if writeErr != nil {
			return writeErr
		}
		return nil
	}

	return fmt.Errorf("decrypt protected path %q: %w", req.Path, err)
}
