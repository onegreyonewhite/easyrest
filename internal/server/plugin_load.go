package server

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func expandHomePath(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, path[2:]), nil
}

func resolveNamedPluginPath(pluginName, configuredPath, defaultExecName string) (absPath string, searchOrigin string, err error) {
	if configuredPath != "" {
		searchOrigin = configuredPath
		candidatePath, expErr := expandHomePath(configuredPath)
		if expErr != nil {
			return "", searchOrigin, fmt.Errorf("error getting home directory for plugin %s: %w", pluginName, expErr)
		}
		verifiedPath, checkErr := checkFile(candidatePath)
		if checkErr == nil {
			absPath, err = filepath.Abs(verifiedPath)
			return absPath, searchOrigin, err
		}
		foundPath, findErr := findPluginPath(candidatePath)
		if findErr == nil {
			absPath, err = filepath.Abs(foundPath)
			return absPath, searchOrigin, err
		}
		return "", searchOrigin, fmt.Errorf("path '%s' not directly executable (err: %v) and not found via search (err: %v)", candidatePath, checkErr, findErr)
	}

	searchOrigin = defaultExecName
	foundPath, findErr := findPluginPath(defaultExecName)
	if findErr != nil {
		return "", searchOrigin, fmt.Errorf("default executable '%s' not found: %w", defaultExecName, findErr)
	}
	absPath, err = filepath.Abs(foundPath)
	return absPath, searchOrigin, err
}

func startPluginRPCClient(absPath string, plugins map[string]hplugin.Plugin, noPluginLog bool) (*hplugin.Client, hplugin.ClientProtocol, error) {
	pluginClientConfig := hplugin.ClientConfig{
		HandshakeConfig:  easyrest.Handshake,
		Plugins:          plugins,
		Cmd:              exec.Command(absPath),
		AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolNetRPC},
	}
	if noPluginLog {
		pluginClientConfig.Logger = hclog.New(&hclog.LoggerOptions{
			Output: io.Discard,
		})
	}
	client := hplugin.NewClient(&pluginClientConfig)
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, nil, err
	}
	return client, rpcClient, nil
}

func checkFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("file is not executable: %s", path)
	}
	return path, nil
}

// findPluginPath searches for a plugin executable in various locations:
// 1. In PATH
// 2. In current working directory
// 3. In the same directory as the current executable
// For each location, it checks both the base name and OS-specific name
func findPluginPath(pluginExec string) (string, error) {
	// Get OS and architecture for OS-specific plugin name
	osName := runtime.GOOS
	archName := runtime.GOARCH
	osSpecificName := fmt.Sprintf("%s-%s-%s", pluginExec, osName, archName)

	// 1. Search in PATH
	if basePath, err := exec.LookPath(pluginExec); err == nil {
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
	}
	if basePath, err := exec.LookPath(osSpecificName); err == nil {
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
	}

	// 2. Search in current working directory
	cwd, err := os.Getwd()
	if err == nil {
		basePath := filepath.Join(cwd, pluginExec)
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
		osSpecificPath := filepath.Join(cwd, osSpecificName)
		if path, err := checkFile(osSpecificPath); err == nil {
			return path, nil
		}
	}

	// 3. Search in the same directory as the current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		basePath := filepath.Join(execDir, pluginExec)
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
		osSpecificPath := filepath.Join(execDir, osSpecificName)
		if path, err := checkFile(osSpecificPath); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("plugin not found: %s", pluginExec)
}
