//go:build !unix

package spec

import (
	"encoding/json"
	"io"
	"os"
)

func readJSONCache[V any](path string) map[string]V {
	cache := map[string]V{}
	if path == "" {
		return cache
	}
	usable := func(info os.FileInfo) bool {
		return info.Mode().IsRegular() && info.Size() <= specMaxSize
	}
	before, err := os.Lstat(path)
	if err != nil || !usable(before) {
		return cache
	}
	f, err := os.Open(path)
	if err != nil {
		return cache
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !usable(after) || !os.SameFile(before, after) {
		return cache
	}
	data, err := io.ReadAll(io.LimitReader(f, specMaxSize+1))
	if err != nil || len(data) > specMaxSize {
		return cache
	}
	var cached map[string]V
	if json.Unmarshal(data, &cached) == nil && cached != nil {
		return cached
	}
	return cache
}
