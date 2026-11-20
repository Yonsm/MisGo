// Package spec queries the public MIoT specification registry (miot-spec.org),
// caches model indices and optional per-model instances, and formats readable
// text or Python enum listings. It has no dependency on account or miio.
package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	RegistryURL = "https://miot-spec.org/miot-spec-v2"
	specMaxSize = 32 << 20
)

var defaultHTTPClient = &http.Client{Timeout: 15 * time.Second}

// DefaultIndexCachePath returns the MiService-compatible temp-file cache path
// for the full model-to-URN index.
func DefaultIndexCachePath() string {
	return filepath.Join(os.TempDir(), "miservice_miot_specs.json")
}

// Option configures a spec Client.
type Option func(*Client)

// WithBaseURL overrides the MIoT spec registry base URL.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(baseURL, "/") }
}

// WithHTTPClient sets the HTTP client used for registry requests.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) { c.http = client }
}

// WithIndexCache enables disk caching of the model-to-URN index at path.
func WithIndexCache(path string) Option {
	return func(c *Client) { c.indexCachePath = path }
}

// WithInstanceCache enables disk caching of individual model spec JSON documents at path.
func WithInstanceCache(path string) Option {
	return func(c *Client) { c.instanceCachePath = path }
}

// Client queries the public MIoT registry and caches its model index and
// optional per-model instances. Its zero value uses the public registry with
// an in-memory cache and a 15-second HTTP timeout.
type Client struct {
	baseURL           string
	http              *http.Client
	indexCachePath    string
	instanceCachePath string

	indexMu   sync.Mutex
	index     map[string]string
	indexLoad *specIndexLoad

	instMu        sync.Mutex
	instWriteMu   sync.Mutex
	instances     map[string]json.RawMessage
	instanceLoads map[string]*specInstanceLoad
}

type specIndexLoad struct {
	done      chan struct{}
	index     map[string]string
	err       error
	abandoned bool
}

type specInstanceLoad struct {
	done      chan struct{}
	raw       json.RawMessage
	err       error
	abandoned bool
}

// New creates a spec Client with the given options.
func New(options ...Option) *Client {
	c := &Client{}
	for _, opt := range options {
		opt(c)
	}
	return c
}

// Resolve looks up matching model-to-URN entries for keyword.
func (s *Client) Resolve(ctx context.Context, keyword string) (map[string]string, error) {
	return s.matchModels(ctx, keyword)
}

// Raw returns the raw JSON for a unique model/URN instance (using the optional
// instance cache with per-model request deduplication), or a JSON-encoded map
// of matching models when zero or multiple models match.
func (s *Client) Raw(ctx context.Context, model string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if model != "" && s.instanceCachePath != "" {
		return s.rawCached(ctx, model)
	}
	raw, _, err := s.fetchRaw(ctx, model)
	return raw, err
}

func (s *Client) rawCached(ctx context.Context, model string) (json.RawMessage, error) {
	var pending *specInstanceLoad
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.instMu.Lock()
		if s.instances == nil {
			s.instances = readJSONCache[json.RawMessage](s.instanceCachePath)
		}
		if cached := s.instances[model]; len(cached) > 0 && cached[0] == '{' {
			s.instMu.Unlock()
			return bytes.Clone(cached), nil
		}
		if s.instanceLoads == nil {
			s.instanceLoads = make(map[string]*specInstanceLoad)
		}
		pending = s.instanceLoads[model]
		if pending == nil {
			pending = &specInstanceLoad{done: make(chan struct{})}
			s.instanceLoads[model] = pending
			s.instMu.Unlock()
			break
		}
		s.instMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			if pending.abandoned {
				continue
			}
			return bytes.Clone(pending.raw), pending.err
		}
	}

	raw, isInstance, err := s.fetchRaw(ctx, model)
	needWrite := false
	s.instMu.Lock()
	if err == nil && isInstance {
		s.instances[model] = bytes.Clone(raw)
		needWrite = true
	}
	pending.raw, pending.err = raw, err
	pending.abandoned = err != nil && ctx.Err() != nil
	delete(s.instanceLoads, model)
	close(pending.done)
	s.instMu.Unlock()
	if needWrite {
		s.instWriteMu.Lock()
		s.instMu.Lock()
		snapshot := maps.Clone(s.instances)
		s.instMu.Unlock()
		writeJSONCache(s.instanceCachePath, snapshot)
		s.instWriteMu.Unlock()
	}
	return bytes.Clone(raw), err
}

func (s *Client) fetchRaw(ctx context.Context, model string) (json.RawMessage, bool, error) {
	urn := model
	if !strings.HasPrefix(model, "urn") {
		matches, err := s.matchModels(ctx, model)
		if err != nil {
			return nil, false, err
		}
		if len(matches) != 1 {
			raw, err := json.Marshal(matches)
			return raw, false, err
		}
		for _, urn = range matches {
		}
	}
	endpoint := "/instance?" + url.Values{"type": {urn}}.Encode()
	var raw json.RawMessage
	if err := s.fetch(ctx, endpoint, &raw); err != nil {
		return nil, false, err
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false, errors.New("MIoT spec instance is not a JSON object")
	}
	return raw, true, nil
}

// Spec looks up a device by model, model substring, or type URN.
// It returns a model-to-URN map for zero or multiple matches. A unique instance
// is returned as raw JSON when format is empty, or as a "text" or "python" listing.
func (s *Client) Spec(ctx context.Context, model, format string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	urn := model
	if !strings.HasPrefix(model, "urn") {
		matches, err := s.matchModels(ctx, model)
		if err != nil {
			return nil, err
		}
		if len(matches) != 1 {
			return matches, nil
		}
		for _, urn = range matches {
		}
	}
	raw, err := s.Raw(ctx, urn)
	if err != nil {
		return nil, err
	}
	if format == "" {
		return raw, nil
	}
	var instance struct{ Services []specService }
	if err := json.Unmarshal(raw, &instance); err != nil {
		return nil, fmt.Errorf("invalid MIoT spec instance: %w", err)
	}
	if instance.Services == nil {
		return nil, errors.New("MIoT spec instance has no services")
	}
	return formatSpec(instance.Services, format == "python", s.registry()+"/instance?type="+urn), nil
}

func (s *Client) registry() string {
	if s.baseURL == "" {
		return RegistryURL
	}
	return s.baseURL
}

func (s *Client) httpClient() *http.Client {
	if s.http != nil {
		return s.http
	}
	return defaultHTTPClient
}

func (s *Client) fetch(ctx context.Context, endpoint string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.registry()+endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MIoT spec registry returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, specMaxSize+1))
	if err != nil {
		return err
	}
	if len(body) > specMaxSize {
		return errors.New("MIoT spec response exceeds size limit")
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("invalid MIoT spec response: %w", err)
	}
	return nil
}

func (s *Client) matchModels(ctx context.Context, keyword string) (map[string]string, error) {
	var load *specIndexLoad
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.indexMu.Lock()
		if s.index == nil {
			s.index = readJSONCache[string](s.indexCachePath)
		}
		if matches := filterSpecModels(s.index, keyword); len(matches) > 0 {
			s.indexMu.Unlock()
			return matches, nil
		}
		load = s.indexLoad
		if load == nil {
			load = &specIndexLoad{done: make(chan struct{})}
			s.indexLoad = load
			s.indexMu.Unlock()
			break
		}
		s.indexMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-load.done:
			if load.abandoned {
				continue
			}
			if load.err != nil {
				return nil, load.err
			}
			return filterSpecModels(load.index, keyword), nil
		}
	}

	index, err := s.fetchSpecIndex(ctx)
	if err == nil && s.indexCachePath != "" {
		writeJSONCache(s.indexCachePath, index)
	}
	s.indexMu.Lock()
	if err == nil {
		s.index = index
	}
	load.index, load.err = index, err
	load.abandoned = err != nil && ctx.Err() != nil
	s.indexLoad = nil
	close(load.done)
	s.indexMu.Unlock()
	if err != nil {
		return nil, err
	}
	return filterSpecModels(index, keyword), nil
}

func filterSpecModels(index map[string]string, keyword string) map[string]string {
	if urn := index[keyword]; keyword != "" && urn != "" {
		return map[string]string{keyword: urn}
	}
	matches := map[string]string{}
	for model, urn := range index {
		if strings.Contains(model, keyword) {
			matches[model] = urn
		}
	}
	return matches
}

func (s *Client) fetchSpecIndex(ctx context.Context) (map[string]string, error) {
	var raw struct {
		Instances []struct{ Model, Type string }
	}
	if err := s.fetch(ctx, "/instances?status=all", &raw); err != nil {
		return nil, err
	}
	if raw.Instances == nil {
		return nil, errors.New("MIoT registry response has no instances")
	}
	index := make(map[string]string, len(raw.Instances))
	for _, entry := range raw.Instances {
		if entry.Model != "" && entry.Type != "" {
			index[entry.Model] = entry.Type
		}
	}
	return index, nil
}

func writeJSONCache(path string, data any) {
	f, err := os.CreateTemp(filepath.Dir(path), ".miot-spec-*")
	if err != nil {
		return // Cache failures do not prevent public lookups.
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(data)
	if closeErr := f.Close(); err == nil && closeErr == nil {
		_ = os.Rename(f.Name(), path)
	}
}

type specService struct {
	IID         int
	Description string
	Properties  []struct {
		IID                 int
		Description, Format string
		Access              []string
		ValueRange          []json.RawMessage `json:"value-range"`
		ValueList           []struct {
			Description string
			Value       json.RawMessage
		} `json:"value-list"`
	}
	Actions []struct {
		IID         int
		Description string
		In, Out     []int
	}
}

func specName(value string) string { return strings.ReplaceAll(value, " ", "_") }

func specDescription(desc string) (string, string) {
	if i := strings.IndexAny(desc, "-—{「[【(（<《"); i >= 0 {
		return specName(desc[:i]), "  # " + desc[i:]
	}
	return specName(desc), ""
}

func specValue(raw json.RawMessage) string {
	switch string(raw) {
	case "true":
		return "True"
	case "false":
		return "False"
	case "null":
		return "None"
	default:
		return string(raw)
	}
}

// pythonSpecName uses only non-normalizing identifier characters; registry text
// must never become Python syntax or a special Enum member.
func pythonSpecName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || unicode.Is(unicode.Han, r) {
			return r
		}
		return '_'
	}, name)
	if name == "" {
		return "_"
	}
	if name[0] == '_' && (name != "_" && (strings.HasSuffix(name, "_") || strings.HasPrefix(name, "__"))) {
		name = "X" + name
	}
	if name[0] >= '0' && name[0] <= '9' {
		return "_" + name
	}
	switch name {
	case "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield", "tuple", "int", "Enum", "ALL_SVCS", "mro":
		return "_" + name
	}
	return name
}

func uniquePythonSpecName(name string, used map[string]bool) string {
	name = pythonSpecName(name)
	candidate := name
	for suffix := 2; used[candidate]; suffix++ {
		candidate = name + "_" + strconv.Itoa(suffix)
	}
	used[candidate] = true
	return candidate
}

func specSingleLine(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, text)
}

func pythonSpecValue(raw json.RawMessage) (string, bool) {
	text := string(raw)
	if text == "true" || text == "false" {
		return specValue(raw), true
	}
	if text == "" || !strings.ContainsRune("-0123456789", rune(text[0])) {
		return "", false
	}
	if !strings.ContainsAny(text, ".eE") {
		return text, len(strings.TrimPrefix(text, "-")) <= 640
	}
	value, err := strconv.ParseFloat(text, 64)
	return text, err == nil && !math.IsInf(value, 0)
}

func formatSpec(services []specService, python bool, endpoint string) string {
	type value struct{ key, repr string }
	type enum struct {
		name   string
		values []value
	}
	var b strings.Builder
	var names []string
	var enums []enum
	if python {
		endpoint = specSingleLine(endpoint)
		endpoint = strings.NewReplacer("coding:", "coding%3A", "coding=", "coding%3D").Replace(endpoint)
	}
	fmt.Fprintf(&b, "# Generated by https://github.com/Yonsm/MiService\n# %s\n\n", endpoint)
	if python {
		b.WriteString("from enum import Enum\n\n")
	}
	types := map[string]bool{}
	for _, svc := range services {
		name := specName(svc.Description)
		if python {
			name = uniquePythonSpecName(name, types)
		}
		names = append(names, name)
		if python {
			fmt.Fprintf(&b, "\nclass %s(tuple, Enum):\n", name)
			if len(svc.Properties)+len(svc.Actions) == 0 {
				b.WriteString("    pass\n")
			}
		} else {
			fmt.Fprintf(&b, "%s = %d\n", name, svc.IID)
		}
		used := map[string]bool{}
		line := func(iid int, name, comment string, readable bool) {
			if !readable {
				name = "_" + name
			}
			if python {
				fmt.Fprintf(&b, "    %s = (%d, %d)%s\n", uniquePythonSpecName(name, used), svc.IID, iid, specSingleLine(comment))
			} else {
				fmt.Fprintf(&b, "    %s = %d%s\n", name, iid, comment)
			}
		}
		for _, prop := range svc.Properties {
			propName, comment := specDescription(prop.Description)
			if prop.Format != "" && prop.Format != "string" {
				comment += "  # " + prop.Format
			}
			var access strings.Builder
			for _, flag := range prop.Access {
				for _, r := range flag {
					access.WriteRune(r)
					break
				}
			}
			if flags := access.String(); flags != "" && flags != "r" {
				comment += "  # " + flags
			}
			line(prop.IID, propName, comment, slices.Contains(prop.Access, "read"))

			var values []value
			switch {
			case prop.ValueRange != nil:
				keys := [...]string{"MIN", "MAX", "STEP"}
				for i, raw := range prop.ValueRange[:min(len(prop.ValueRange), len(keys))] {
					if n, _ := strconv.ParseFloat(string(raw), 64); i == 2 && (n == 1 || string(raw) == "true") {
						continue
					}
					repr := specValue(raw)
					if python {
						if safe, ok := pythonSpecValue(raw); ok {
							repr = safe
						} else {
							continue
						}
					}
					values = append(values, value{keys[i], repr})
				}
			case prop.ValueList != nil:
				positions := make(map[string]int, len(prop.ValueList))
				for _, item := range prop.ValueList {
					key, repr := specName(item.Description), specValue(item.Value)
					if key == "" {
						key = repr
					}
					if python {
						var ok bool
						if repr, ok = pythonSpecValue(item.Value); !ok {
							continue
						}
					}
					if at, ok := positions[key]; ok {
						values[at].repr = repr
					} else {
						positions[key] = len(values)
						values = append(values, value{key, repr})
					}
				}
			default:
				continue
			}
			enums = append(enums, enum{name + "_" + propName, values})
		}
		if svc.Actions != nil {
			b.WriteByte('\n')
			for _, action := range svc.Actions {
				name, comment := specDescription(action.Description)
				if len(action.In) > 0 {
					comment += "  # in=" + specIDs(action.In)
				}
				if len(action.Out) > 0 {
					comment += "  # out=" + specIDs(action.Out)
				}
				line(action.IID, name, comment, false)
			}
		}
		b.WriteByte('\n')
	}
	for _, enum := range enums {
		if python {
			fmt.Fprintf(&b, "\nclass %s(int, Enum):\n", uniquePythonSpecName(enum.name, types))
			if len(enum.values) == 0 {
				b.WriteString("    pass\n")
			}
		} else {
			fmt.Fprintln(&b, enum.name)
		}
		used := map[string]bool{}
		for _, v := range enum.values {
			if python {
				v.key = uniquePythonSpecName(v.key, used)
			} else if v.key != "" && strings.IndexFunc(v.key, func(r rune) bool { return !unicode.IsDigit(r) }) < 0 {
				v.key = "_" + v.key
			}
			fmt.Fprintf(&b, "    %s = %s\n", v.key, v.repr)
		}
		b.WriteByte('\n')
	}
	if python {
		fmt.Fprintf(&b, "\nALL_SVCS = (%s)\n", strings.Join(names, ", "))
	}
	return b.String()
}

func specIDs(ids []int) string {
	ss := make([]string, len(ids))
	for i, id := range ids {
		ss[i] = strconv.Itoa(id)
	}
	return "[" + strings.Join(ss, ", ") + "]"
}
