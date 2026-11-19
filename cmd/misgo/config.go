package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Version is the MisGo version, independent of the Python MiService version.
// Release builds override it with -ldflags "-X main.Version=...".
var Version = "0.1.1"

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
	i := strings.LastIndex(c.Local, ":")
	if i <= 0 || i == len(c.Local)-1 {
		return "", "", errors.New("MI_LOCAL must be <IP>:<Token>")
	}
	return c.Local[:i], c.Local[i+1:], nil
}

// HomeTokenPath returns the CLI's Python-compatible token cache path.
func HomeTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		current, userErr := user.Current()
		if userErr != nil || current.HomeDir == "" {
			return "", err
		}
		home = current.HomeDir
	}
	return filepath.Join(home, ".mi.token"), nil
}
