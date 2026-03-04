package filter_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/rbo13/git-age-filter/internal/crypto"
	"github.com/rbo13/git-age-filter/internal/filter"
	"github.com/rbo13/git-age-filter/internal/policy"
)

func TestCleanPassThroughWhenPathDoesNotMatch(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	cfg := testPolicy(t, recipient.String(), writeIdentityFile(t, id.String()), policy.OnMissingIdentityFail)

	input := []byte("HELLO=WORLD")
	req := filter.CleanRequest{
		Path:   "README.md",
		Input:  bytes.NewReader(input),
		Policy: cfg,
	}

	var out bytes.Buffer
	err := filter.Clean(req, &out)
	if err != nil {
		t.Fatalf("Clean() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), input) {
		t.Fatalf("clean output = %q; want passthrough %q", out.Bytes(), input)
	}
}

func TestCleanEncryptsWhenPathMatches(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	cfg := testPolicy(t, recipient.String(), writeIdentityFile(t, id.String()), policy.OnMissingIdentityFail)

	plain := []byte("DB_PASSWORD=secret")
	req := filter.CleanRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(plain),
		Policy: cfg,
	}

	var out bytes.Buffer
	err := filter.Clean(req, &out)
	if err != nil {
		t.Fatalf("Clean() returned error: %v", err)
	}
	if bytes.Equal(out.Bytes(), plain) {
		t.Fatal("clean output unexpectedly equals plaintext")
	}
	if !bytes.Contains(out.Bytes(), []byte("BEGIN AGE ENCRYPTED FILE")) {
		t.Fatalf("clean output does not look armored: %q", out.String())
	}
}

func TestCleanPassesPlaintextWhenRuleNotRequired(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)
	cfg := &policy.File{
		Version: 1,
		Defaults: policy.Defaults{
			Armored:           true,
			OnMissingIdentity: policy.OnMissingIdentityFail,
			MaxFileSize:       policy.DefaultMaxFileSize,
		},
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{recipient.String()},
				Required:   false,
			},
		},
	}

	plain := []byte("DB_PASSWORD=secret")
	var out bytes.Buffer
	err := filter.Clean(filter.CleanRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(plain),
		Policy: cfg,
	}, &out)
	if err != nil {
		t.Fatalf("Clean() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("Clean() output=%q; want %q", out.Bytes(), plain)
	}
}

func TestCleanRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	cfg := testPolicy(t, recipient.String(), writeIdentityFile(t, id.String()), policy.OnMissingIdentityFail)
	cfg.Defaults.MaxFileSize = 4

	var out bytes.Buffer
	err := filter.Clean(filter.CleanRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader([]byte("TOO-LARGE")),
		Policy: cfg,
	}, &out)
	if err == nil {
		t.Fatal("Clean() expected max_file_size error")
	}
	if !errors.Is(err, filter.ErrFileTooLarge) {
		t.Fatalf("Clean() error=%v; want ErrFileTooLarge", err)
	}
}

func TestSmudgeDecryptsWhenPathMatches(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	identityPath := writeIdentityFile(t, id.String())
	cfg := testPolicy(t, recipient.String(), identityPath, policy.OnMissingIdentityFail)

	plain := []byte("TOKEN=abc123")
	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewReader(plain), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}

	req := filter.SmudgeRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(cipher.Bytes()),
		Policy: cfg,
	}

	var out bytes.Buffer
	err = filter.Smudge(req, &out)
	if err != nil {
		t.Fatalf("Smudge() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("smudge output = %q; want %q", out.Bytes(), plain)
	}
}

func TestSmudgeRequiredRejectsPlaintext(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	cfg := testPolicy(t, recipient.String(), writeIdentityFile(t, id.String()), policy.OnMissingIdentityFail)

	req := filter.SmudgeRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewBufferString("NOT_ENCRYPTED"),
		Policy: cfg,
	}

	var out bytes.Buffer
	err := filter.Smudge(req, &out)
	if err == nil {
		t.Fatal("Smudge() expected error for required plaintext; got nil")
	}
}

func TestSmudgePassesCiphertextWhenIdentityMissingAndPolicyAllowsPass(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)

	plain := []byte("K=V")
	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewReader(plain), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}

	cfgNoIdentity := testPolicy(t, recipient.String(), "", policy.OnMissingIdentityPass)
	req := filter.SmudgeRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(cipher.Bytes()),
		Policy: cfgNoIdentity,
	}

	var out bytes.Buffer
	err = filter.Smudge(req, &out)
	if err != nil {
		t.Fatalf("Smudge() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), cipher.Bytes()) {
		t.Fatalf("smudge output should remain ciphertext when identities missing and pass is enabled")
	}
}

func TestCleanRequiresPolicy(t *testing.T) {
	t.Parallel()

	err := filter.Clean(filter.CleanRequest{
		Path:  "secrets/app.env",
		Input: bytes.NewBufferString("x"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("Clean() expected error when policy is nil")
	}
}

func TestSmudgeRequiresPolicy(t *testing.T) {
	t.Parallel()

	err := filter.Smudge(filter.SmudgeRequest{
		Path:  "secrets/app.env",
		Input: bytes.NewBufferString("x"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("Smudge() expected error when policy is nil")
	}
}

func TestSmudgeMissingIdentityFailsWhenPolicyRequiresFail(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)

	plain := []byte("FOO=BAR")
	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewReader(plain), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}

	cfg := testPolicy(t, recipient.String(), "", policy.OnMissingIdentityFail)
	req := filter.SmudgeRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(cipher.Bytes()),
		Policy: cfg,
	}

	var out bytes.Buffer
	err = filter.Smudge(req, &out)
	if err == nil {
		t.Fatal("Smudge() expected error when identities are missing and policy requires fail")
	}
}

func TestCleanPassesThroughExistingCiphertext(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	cfg := testPolicy(t, recipient.String(), writeIdentityFile(t, id.String()), policy.OnMissingIdentityFail)

	cipher := []byte("-----BEGIN AGE ENCRYPTED FILE-----\n...")
	var out bytes.Buffer
	err := filter.Clean(filter.CleanRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(cipher),
		Policy: cfg,
	}, &out)
	if err != nil {
		t.Fatalf("Clean() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), cipher) {
		t.Fatal("Clean() should pass through already-encrypted input")
	}
}

func TestSmudgePassesPlaintextWhenRuleNotRequired(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)
	cfg := &policy.File{
		Version: 1,
		Defaults: policy.Defaults{
			OnMissingIdentity: policy.OnMissingIdentityFail,
		},
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{recipient.String()},
				Required:   false,
			},
		},
	}

	var out bytes.Buffer
	err := filter.Smudge(filter.SmudgeRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewBufferString("PLAIN=value"),
		Policy: cfg,
	}, &out)
	if err != nil {
		t.Fatalf("Smudge() returned error: %v", err)
	}
	if got := out.String(); got != "PLAIN=value" {
		t.Fatalf("Smudge() output=%q; want %q", got, "PLAIN=value")
	}
}

func TestCleanReusesExistingIndexCiphertextWhenPlaintextMatches(t *testing.T) {
	t.Parallel()

	id, recipient := generateIdentityPair(t)
	identityPath := writeIdentityFile(t, id.String())
	cfg := testPolicy(t, recipient.String(), identityPath, policy.OnMissingIdentityFail)

	plain := []byte("SHARED=VALUE")
	var existingCipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewReader(plain), &existingCipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}

	var out bytes.Buffer
	err = filter.Clean(filter.CleanRequest{
		Path:   "secrets/app.env",
		Input:  bytes.NewReader(plain),
		Policy: cfg,
		IndexBlobLookup: func(path string) ([]byte, error) {
			if path != "secrets/app.env" {
				t.Fatalf("readIndexBlob() path=%q; want %q", path, "secrets/app.env")
			}
			return existingCipher.Bytes(), nil
		},
	}, &out)
	if err != nil {
		t.Fatalf("Clean() returned error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), existingCipher.Bytes()) {
		t.Fatal("Clean() should reuse existing index ciphertext when plaintext matches")
	}
}

func testPolicy(t *testing.T, recipient string, identityPath string, onMissingIdentity string) *policy.File {
	t.Helper()

	identities := []string{}
	if identityPath != "" {
		identities = append(identities, identityPath)
	}

	return &policy.File{
		Version: 1,
		Defaults: policy.Defaults{
			Armored:           true,
			MaxFileSize:       policy.DefaultMaxFileSize,
			OnMissingIdentity: onMissingIdentity,
		},
		Identities: identities,
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{recipient},
				Required:   true,
			},
		},
	}
}

func generateIdentityPair(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error: %v", err)
	}
	return identity, identity.Recipient()
}

func writeIdentityFile(t *testing.T, content string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(file, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	return file
}
