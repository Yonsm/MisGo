package spec

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInstanceCache(t *testing.T) {
	var hits atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body string
			switch r.URL.Path {
			case "/instances":
				body = `{"instances":[{"model":"demo.light.v1","type":"urn:miot-spec-v2:device:light:0000A001:demo-v1:1"}]}`
			case "/instance":
				hits.Add(1)
				body = `{"type":"urn:miot-spec-v2:device:light:0000A001:demo-v1:1","services":[{"iid":2,"description":"Light","properties":[{"iid":1,"description":"Switch Status","format":"bool","access":["read","write"]}]}]}`
			default:
				return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}),
	}

	dir := t.TempDir()
	instCache := filepath.Join(dir, "instances.json")
	idxCache := filepath.Join(dir, "index.json")

	c1 := New(WithBaseURL("https://spec.example"), WithHTTPClient(client), WithIndexCache(idxCache), WithInstanceCache(instCache))
	raw1, err := c1.Raw(context.Background(), "demo.light.v1")
	if err != nil || len(raw1) == 0 {
		t.Fatalf("first Raw failed: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 registry hit, got %d", hits.Load())
	}

	// Second client reads directly from the on-disk instance cache without hitting /instance.
	c2 := New(WithBaseURL("https://spec.example"), WithHTTPClient(client), WithIndexCache(idxCache), WithInstanceCache(instCache))
	raw2, err := c2.Raw(context.Background(), "demo.light.v1")
	if err != nil || string(raw2) != string(raw1) {
		t.Fatalf("cached Raw mismatch: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected cached read without extra hit, got %d", hits.Load())
	}
}
