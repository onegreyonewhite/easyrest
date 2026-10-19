package cli

import (
	"flag"
	"fmt"
	"strings"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// ParseFlags reads repeated -config paths and optional overrides.
// Only flags the user set are returned in the YAML overlay.
func ParseFlags() (configFiles []string, overrideYAML string, err error) {
	var configs stringList
	flag.Var(&configs, "config", "Path to a configuration file (repeatable)")
	port := flag.String("port", "", "Server port")
	accessLog := flag.Bool("access-log", false, "Enable access logging")
	pluginLog := flag.Bool("plugin-log", false, "Enable plugin logging")
	flag.Parse()

	var b strings.Builder
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "port":
			fmt.Fprintf(&b, "port: %q\n", *port)
		case "access-log":
			if *accessLog {
				b.WriteString("access_log: true\n")
			}
		case "plugin-log":
			if *pluginLog {
				b.WriteString("plugin_log: true\n")
			}
		}
	})
	return []string(configs), b.String(), nil
}
