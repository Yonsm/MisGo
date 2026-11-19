// Package misgo provides Xiaomi account, MiIO, MIoT, and MiNA clients.
package misgo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Version is the MisGo version, independent of the Python MiService version.
const Version = "0.1.0"

// Config holds the MiService environment settings used by the command line.
// Local takes precedence over cloud settings when it is nonempty.
type Config struct {
	Username string
	Password string
	DID      string
	Local    string
}

// ConfigFromEnv reads MI_USER, MI_PASS, MI_DID, and MI_LOCAL.
func ConfigFromEnv() Config {
	return Config{
		Username: os.Getenv("MI_USER"),
		Password: os.Getenv("MI_PASS"),
		DID:      os.Getenv("MI_DID"),
		Local:    os.Getenv("MI_LOCAL"),
	}
}

// LocalTarget splits the MI_LOCAL setting into its address and token.
func (c Config) LocalTarget() (address, token string, err error) {
	address, token, ok := strings.Cut(c.Local, ":")
	if !ok || address == "" || token == "" {
		return "", "", errors.New("MI_LOCAL must be <IP>:<Token>")
	}
	return address, token, nil
}

// HomeTokenPath returns the CLI's Python-compatible token cache path.
func HomeTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultTokenPath), nil
}
