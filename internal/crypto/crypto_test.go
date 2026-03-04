package crypto_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/rbo13/git-age-filter/internal/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	identity, recipient := generateIdentityPair(t)
	identityPath := writeIdentityFile(t, identity.String())

	plain := []byte("DB_PASSWORD=very-secret-value")

	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewReader(plain), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    false,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}
	if bytes.Contains(cipher.Bytes(), plain) {
		t.Fatal("ciphertext unexpectedly contains plaintext")
	}

	var decrypted bytes.Buffer
	err = crypto.Decrypt(bytes.NewReader(cipher.Bytes()), &decrypted, crypto.DecryptOptions{
		IdentityPaths: []string{identityPath},
	})
	if err != nil {
		t.Fatalf("Decrypt() returned error: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatalf("decrypted = %q; want %q", decrypted.Bytes(), plain)
	}
}

func TestEncryptArmored(t *testing.T) {
	t.Parallel()

	identity, recipient := generateIdentityPair(t)
	identityPath := writeIdentityFile(t, identity.String())

	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewBufferString("hello"), &cipher, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
		Armored:    true,
	})
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}
	if !bytes.HasPrefix(cipher.Bytes(), []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatalf("armored output missing expected header: %q", cipher.String())
	}

	var decrypted bytes.Buffer
	err = crypto.Decrypt(bytes.NewReader(cipher.Bytes()), &decrypted, crypto.DecryptOptions{
		IdentityPaths: []string{identityPath},
	})
	if err != nil {
		t.Fatalf("Decrypt() returned error: %v", err)
	}
	if got := decrypted.String(); got != "hello" {
		t.Fatalf("decrypted = %q; want %q", got, "hello")
	}
}

func TestEncryptRequiresRecipients(t *testing.T) {
	t.Parallel()

	var cipher bytes.Buffer
	err := crypto.Encrypt(bytes.NewBufferString("plain"), &cipher, crypto.EncryptOptions{})
	if err == nil {
		t.Fatal("Encrypt() expected error for missing recipients; got nil")
	}
}

func TestDecryptRequiresIdentities(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := crypto.Decrypt(bytes.NewBufferString("cipher"), &out, crypto.DecryptOptions{})
	if err == nil {
		t.Fatal("Decrypt() expected error for missing identities; got nil")
	}
}

func TestEncryptRejectsInvalidRecipient(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := crypto.Encrypt(bytes.NewBufferString("hello"), &out, crypto.EncryptOptions{
		Recipients: []string{"not-a-valid-recipient"},
	})
	if err == nil {
		t.Fatal("Encrypt() expected error for invalid recipient; got nil")
	}
}

func TestIsCiphertextDetection(t *testing.T) {
	t.Parallel()

	if crypto.IsCiphertext([]byte("age-encryption.org/v1\n")) == false {
		t.Fatal("IsCiphertext() should detect binary age header")
	}
	if crypto.IsCiphertext([]byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) == false {
		t.Fatal("IsCiphertext() should detect armored age header")
	}
	if crypto.IsCiphertext([]byte("plain text")) == true {
		t.Fatal("IsCiphertext() should be false for plaintext")
	}
}

func TestExpandHome(t *testing.T) {
	t.Parallel()

	path, err := crypto.ExpandHome("~/keys.txt")
	if err != nil {
		t.Fatalf("expandHome() returned error: %v", err)
	}
	if path == "~/keys.txt" {
		t.Fatalf("expandHome() did not expand home: %q", path)
	}
}

func TestExpandHomeTildeOnly(t *testing.T) {
	t.Parallel()

	path, err := crypto.ExpandHome("~")
	if err != nil {
		t.Fatalf("expandHome(\"~\") returned error: %v", err)
	}
	if path == "~" {
		t.Fatalf("expandHome(\"~\") did not expand home")
	}
}

func TestParseIdentitiesMissingFile(t *testing.T) {
	t.Parallel()

	_, err := crypto.ParseIdentities([]string{"/definitely/missing/keys.txt"})
	if err == nil {
		t.Fatal("parseIdentities() expected error for missing file; got nil")
	}
}

func TestParseRecipientX25519(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)

	parsed, err := crypto.ParseRecipient(recipient.String())
	if err != nil {
		t.Fatalf("parseRecipient() returned error: %v", err)
	}
	if parsed == nil {
		t.Fatal("parseRecipient() returned nil recipient")
	}
}

func TestExpandHomeNoExpansion(t *testing.T) {
	t.Parallel()

	path, err := crypto.ExpandHome("/tmp/keys.txt")
	if err != nil {
		t.Fatalf("expandHome() returned error: %v", err)
	}
	if path != "/tmp/keys.txt" {
		t.Fatalf("expandHome() = %q; want %q", path, "/tmp/keys.txt")
	}
}

func TestParseIdentitiesBlankPathOnly(t *testing.T) {
	t.Parallel()

	_, err := crypto.ParseIdentities([]string{"  "})
	if !errors.Is(err, crypto.ErrNoIdentities) {
		t.Fatalf("parseIdentities() error=%v; want ErrNoIdentities", err)
	}
}

func TestParseIdentitiesRejectsNonLocalPath(t *testing.T) {
	t.Parallel()

	_, err := crypto.ParseIdentities([]string{"https://example.com/keys.txt"})
	if !errors.Is(err, crypto.ErrNonLocalPath) {
		t.Fatalf("ParseIdentities() error=%v; want ErrNonLocalPath", err)
	}
}

func TestIsLocalPath(t *testing.T) {
	t.Parallel()

	if crypto.IsLocalPath("https://example.com/keys.txt") {
		t.Fatal("isLocalPath() should reject URL paths")
	}
	if crypto.IsLocalPath("age-plugin:example") {
		t.Fatal("isLocalPath() should reject plugin URIs")
	}
	if !crypto.IsLocalPath("./keys.txt") {
		t.Fatal("isLocalPath() should accept local paths")
	}
}

func TestEncryptReaderFailure(t *testing.T) {
	t.Parallel()

	_, recipient := generateIdentityPair(t)
	err := crypto.Encrypt(errReader{}, &bytes.Buffer{}, crypto.EncryptOptions{
		Recipients: []string{recipient.String()},
	})
	if err == nil {
		t.Fatal("Encrypt() expected error for failing reader; got nil")
	}
}

func TestDecryptReaderFailure(t *testing.T) {
	t.Parallel()

	identity, _ := generateIdentityPair(t)
	identityPath := writeIdentityFile(t, identity.String())

	err := crypto.Decrypt(errReader{}, &bytes.Buffer{}, crypto.DecryptOptions{
		IdentityPaths: []string{identityPath},
	})
	if err == nil {
		t.Fatal("Decrypt() expected error for failing reader; got nil")
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("forced read error")
}

func generateIdentityPair(t *testing.T) (*age.X25519Identity, *age.X25519Recipient) {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error: %v", err)
	}

	recipient := identity.Recipient()
	return identity, recipient
}

func writeIdentityFile(t *testing.T, content string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(file, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	return file
}
