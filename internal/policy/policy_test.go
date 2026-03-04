package policy_test

import (
	"slices"
	"testing"

	"github.com/rbo13/git-age-filter/internal/policy"
)

const validPolicyYAML = `
version: 1
defaults:
  armored: false
  max_file_size: 10485760
  on_missing_identity: fail
identities:
  - ~/.config/age/keys.txt
recipient_sets:
  team-dev:
    - age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0
rules:
  - path: "secrets/**/*.env"
    recipients: ["team-dev"]
    required: true
  - path: "secrets/prod/*.env"
    recipients: ["age1h90n72mmezxnq5npumjyhn7rfcsu596ppj6hv0kgxhv74ts4gcushu20zj"]
    required: true
`

func TestParseValidPolicy(t *testing.T) {
	t.Parallel()

	got, err := policy.Parse([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if got.Version != 1 {
		t.Fatalf("Version = %d; want 1", got.Version)
	}

	rule := got.Match("secrets/prod/app.env")
	if rule == nil {
		t.Fatal("Match() returned nil; want matching rule")
	}

	if rule.Path != "secrets/prod/*.env" {
		t.Fatalf("Match().Path = %q; want %q", rule.Path, "secrets/prod/*.env")
	}
}

func TestParseRejectsParentTraversal(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
rules:
  - path: "../secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected error for parent traversal path; got nil")
	}
}

func TestMatchLastRuleWins(t *testing.T) {
	t.Parallel()

	got, err := policy.Parse([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	rule := got.Match("secrets/prod/app.env")
	if rule == nil {
		t.Fatal("Match() returned nil")
	}

	if rule.Path != "secrets/prod/*.env" {
		t.Fatalf("Match().Path = %q; want %q", rule.Path, "secrets/prod/*.env")
	}
}

func TestResolvedRecipients(t *testing.T) {
	t.Parallel()

	got, err := policy.Parse([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	rule := got.Match("secrets/dev/app.env")
	if rule == nil {
		t.Fatal("Match() returned nil")
	}

	recipients, err := got.ResolvedRecipients(*rule)
	if err != nil {
		t.Fatalf("ResolvedRecipients() returned error: %v", err)
	}

	want := []string{
		"age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0",
	}
	if !slices.Equal(recipients, want) {
		t.Fatalf("ResolvedRecipients() = %#v; want %#v", recipients, want)
	}
}

func TestMatchNormalizesWindowsSeparators(t *testing.T) {
	t.Parallel()

	got, err := policy.Parse([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	rule := got.Match(`secrets\prod\app.env`)
	if rule == nil {
		t.Fatal("Match() returned nil for windows separators")
	}
}

func TestParseRejectsUnsupportedTopLevelKey(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
unknown: value
rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected error; got nil")
	}
}

func TestParseSupportsBlockRecipients(t *testing.T) {
	t.Parallel()

	const policyYAML = `
version: 1
rules:
  - path: "secrets/*.env"
    recipients:
      - age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0
      - age1h90n72mmezxnq5npumjyhn7rfcsu596ppj6hv0kgxhv74ts4gcushu20zj
    required: true
`
	got, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	rule := got.Match("secrets/app.env")
	if rule == nil {
		t.Fatal("Match() returned nil")
	}
	if len(rule.Recipients) != 2 {
		t.Fatalf("len(rule.Recipients) = %d; want 2", len(rule.Recipients))
	}
}

func TestValidateOnMissingIdentityEnum(t *testing.T) {
	t.Parallel()

	cfg := &policy.File{
		Version: 1,
		Defaults: policy.Defaults{
			OnMissingIdentity: "invalid",
		},
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{"age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error; got nil")
	}
}

func TestNormalizeRulePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ok path", input: "secrets/*.env", want: "secrets/*.env"},
		{name: "windows separators", input: `secrets\*.env`, want: "secrets/*.env"},
		{name: "absolute path", input: "/secrets/*.env", wantErr: true},
		{name: "parent traversal", input: "../secrets/*.env", wantErr: true},
		{name: "empty", input: " ", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policy.NormalizeRulePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeRulePath(%q) expected error; got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("normalizeRulePath(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeRulePath(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseRejectsUnsupportedDefaultsKey(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
defaults:
  unknown: true
rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected error; got nil")
	}
}

func TestParseRejectsUnsupportedRuleKey(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
rules:
  - path: "secrets/*.env"
    bogus: true
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected error; got nil")
	}
}

func TestResolvedRecipientsRejectsEmptyEntries(t *testing.T) {
	t.Parallel()

	cfg := &policy.File{
		RecipientSets: map[string][]string{},
	}
	_, err := cfg.ResolvedRecipients(policy.Rule{
		Recipients: []string{"  "},
	})
	if err == nil {
		t.Fatal("ResolvedRecipients() expected error; got nil")
	}
}

func TestMatchReturnsNilForInvalidInputPath(t *testing.T) {
	t.Parallel()

	got, err := policy.Parse([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if rule := got.Match("../secrets/app.env"); rule != nil {
		t.Fatalf("Match() = %#v; want nil", rule)
	}
}

func TestParseRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
rules:
  - path: "secrets/*.env"
    recipients: [a, b
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected parse error; got nil")
	}
}

func TestParseRejectsMultipleYAMLDocuments(t *testing.T) {
	t.Parallel()

	const badPolicy = `
version: 1
rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]
---
version: 1
rules:
  - path: "other/*.env"
    recipients: ["age1h90n72mmezxnq5npumjyhn7rfcsu596ppj6hv0kgxhv74ts4gcushu20zj"]
`
	_, err := policy.Parse([]byte(badPolicy))
	if err == nil {
		t.Fatal("Parse() expected error for multiple YAML documents; got nil")
	}
}

func TestParseAllowsTrailingWhitespaceOnly(t *testing.T) {
	t.Parallel()

	const policyWithTrailingWhitespace = `
version: 1
rules:
  - path: "secrets/*.env"
    recipients: ["age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"]

    
`
	got, err := policy.Parse([]byte(policyWithTrailingWhitespace))
	if err != nil {
		t.Fatalf("Parse() returned error for trailing whitespace: %v", err)
	}
	if got == nil {
		t.Fatal("Parse() returned nil policy")
	}
}

func TestValidateSetsDefaultMaxFileSize(t *testing.T) {
	t.Parallel()

	cfg := &policy.File{
		Version: 1,
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{"age1lnkct94zs7sz80fqv9kd22jjcv6fjukcnhxphm5fmhtda57tsa0qc7g4w0"},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
	if cfg.Defaults.MaxFileSize != policy.DefaultMaxFileSize {
		t.Fatalf("Defaults.MaxFileSize=%d; want %d", cfg.Defaults.MaxFileSize, policy.DefaultMaxFileSize)
	}
}

func TestValidateRejectsInvalidRecipient(t *testing.T) {
	t.Parallel()

	cfg := &policy.File{
		Version: 1,
		Rules: []policy.Rule{
			{
				Path:       "secrets/*.env",
				Recipients: []string{"invalid-recipient"},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected invalid recipient error")
	}
}
