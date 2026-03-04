package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rbo13/git-age-filter/internal/cli"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no args shows usage",
			args:       nil,
			wantCode:   2,
			wantStderr: "usage:",
		},
		{
			name:       "help command",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "Commands:",
		},
		{
			name:       "version command",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: "git-age-filter",
		},
		{
			name:       "unknown command",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: "unknown command",
		},
		{
			name:       "global flags supported",
			args:       []string{"--verbose", "--no-color", "version"},
			wantCode:   0,
			wantStdout: "git-age-filter",
		},
		{
			name:       "invalid global flag",
			args:       []string{"--bad", "version"},
			wantCode:   2,
			wantStderr: "invalid global flags",
		},
		{
			name:       "clean requires path",
			args:       []string{"clean"},
			wantCode:   2,
			wantStderr: "required",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			got := cli.Run(context.Background(), tt.args, &stdout, &stderr)
			if got != tt.wantCode {
				t.Fatalf("Run(%v) code = %d; want %d", tt.args, got, tt.wantCode)
			}

			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout = %q; want substring %q", stdout.String(), tt.wantStdout)
			}

			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q; want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
