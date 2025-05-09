package cli

import (
	"flag"
	"os"
	"testing"
)

// Helper to reset flags and environment between tests
func resetEnvAndFlags() {
	os.Clearenv()
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		preEnv    map[string]string
		wantEnv   map[string]string
		wantError bool
		version   bool
	}{
		{
			name:    "default run (no flags)",
			args:    []string{"cmd"},
			wantEnv: map[string]string{},
		},
		{
			name:    "set port",
			args:    []string{"cmd", "--port=8081"},
			wantEnv: map[string]string{"ER_PORT": "8081"},
		},
		{
			name:    "set token secret",
			args:    []string{"cmd", "--token-secret=abc123"},
			wantEnv: map[string]string{"ER_TOKEN_SECRET": "abc123"},
		},
		{
			name:    "set plugin",
			args:    []string{"cmd", "--plugin=foo", "--plugin=bar"},
			wantEnv: map[string]string{"ER_PLUGINS": "foo,bar"},
		},
		{
			name: "set CORS flags",
			args: []string{"cmd", "--cors-enabled", "--cors-origins=https://a.com,https://b.com", "--cors-methods=GET,POST", "--cors-headers=Authorization", "--cors-max-age=3600"},
			wantEnv: map[string]string{
				"ER_CORS_ENABLED": "1",
				"ER_CORS_ORIGINS": "https://a.com,https://b.com",
				"ER_CORS_METHODS": "GET,POST",
				"ER_CORS_HEADERS": "Authorization",
				"ER_CORS_MAX_AGE": "3600",
			},
		},
		{
			name:    "set TLS flags",
			args:    []string{"cmd", "--tls-cert-file=cert.pem", "--tls-key-file=key.pem"},
			wantEnv: map[string]string{"ER_TLS_CERT_FILE": "cert.pem", "ER_TLS_KEY_FILE": "key.pem"},
		},
		{
			name:    "set config file",
			args:    []string{"cmd", "--config=cli.go"}, // file exists
			wantEnv: map[string]string{"ER_CONFIG_FILE": "cli.go"},
		},
		{
			name:      "show version",
			args:      []string{"cmd", "--version"},
			wantError: true,
			version:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetEnvAndFlags()
			for k, v := range tt.preEnv {
				os.Setenv(k, v)
			}
			os.Args = tt.args
			if tt.version {
				// Suppress output for version
				old := os.Stdout
				_, w, _ := os.Pipe()
				os.Stdout = w
				_, err := ParseFlags()
				w.Close()
				os.Stdout = old
				if (err != nil) != tt.wantError {
					t.Fatalf("expected error: %v, got: %v", tt.wantError, err)
				}
				return
			}
			_, err := ParseFlags()
			if (err != nil) != tt.wantError {
				t.Fatalf("expected error: %v, got: %v", tt.wantError, err)
			}
			for k, want := range tt.wantEnv {
				got := os.Getenv(k)
				if got != want {
					t.Errorf("env %q: want %q, got %q", k, want, got)
				}
			}
		})
	}
}

// Additional edge case: config file does not exist
func TestParseFlags_ConfigFileNotExist(t *testing.T) {
	resetEnvAndFlags()
	os.Args = []string{"cmd", "--config=not_a_real_file_123456789"}
	_, err := ParseFlags()
	if err != nil {
		t.Errorf("should not error if config file does not exist, got: %v", err)
	}
	if os.Getenv("ER_CONFIG_FILE") != "" {
		t.Errorf("ER_CONFIG_FILE should not be set if file does not exist")
	}
}
