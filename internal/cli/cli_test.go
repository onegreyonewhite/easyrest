package cli

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantFiles []string
		wantYAML  string
		absent    []string
	}{
		{
			name: "no flags",
			args: []string{"cmd"},
		},
		{
			name:      "repeated config",
			args:      []string{"cmd", "-config", "a.yaml", "-config", "b.yaml"},
			wantFiles: []string{"a.yaml", "b.yaml"},
		},
		{
			name:     "port",
			args:     []string{"cmd", "-port", "8081"},
			wantYAML: "port: \"8081\"\n",
			absent:   []string{"access_log", "plugin_log"},
		},
		{
			name:     "access log only",
			args:     []string{"cmd", "-access-log"},
			wantYAML: "access_log: true\n",
			absent:   []string{"plugin_log", "port:"},
		},
		{
			name:     "plugin log only",
			args:     []string{"cmd", "-plugin-log"},
			wantYAML: "plugin_log: true\n",
			absent:   []string{"access_log"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetFlags()
			os.Args = tt.args
			files, overlay, err := ParseFlags()
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != len(tt.wantFiles) {
				t.Fatalf("files %#v, want %#v", files, tt.wantFiles)
			}
			for i := range tt.wantFiles {
				if files[i] != tt.wantFiles[i] {
					t.Fatalf("files %#v, want %#v", files, tt.wantFiles)
				}
			}
			if tt.wantYAML != "" && overlay != tt.wantYAML {
				t.Fatalf("overlay %q, want %q", overlay, tt.wantYAML)
			}
			if tt.wantYAML == "" && overlay != "" {
				t.Fatalf("overlay %q, want empty", overlay)
			}
			for _, key := range tt.absent {
				if strings.Contains(overlay, key) {
					t.Fatalf("overlay %q contains %q", overlay, key)
				}
			}
		})
	}
}
