package hibp

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sha1Upper(s string) string {
	sum := sha1.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestHashPassword(t *testing.T) {
	// Known SHA-1 for "password" (uppercase hex).
	got := hashPassword("password")
	want := "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	if got != want {
		t.Fatalf("hashPassword(password) = %s, want %s", got, want)
	}
}

func TestCheckPasswordFoundAndNotFound(t *testing.T) {
	password := "password"
	hash := sha1Upper(password)
	prefix, suffix := hash[:5], hash[5:]

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		switch r.URL.Path {
		case "/range/" + prefix:
			_, _ = io.WriteString(w, "AAAAABBBBBCCCCCDDDDDEEEEE:10\n"+suffix+":42\nFFFFFGGGGGHHHHHIIIIIJJJJJ:1\n")
		default:
			_, _ = io.WriteString(w, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n")
		}
	}))
	defer srv.Close()

	client := NewClient(false, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithWait(0))

	found, err := client.CheckPassword(password, false)
	if err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}
	if !found {
		t.Fatal("expected password to be found")
	}
	if gotUA != userAgent {
		t.Fatalf("User-Agent = %q, want %q", gotUA, userAgent)
	}

	found, err = client.CheckPassword("this-password-is-unique-xyz", false)
	if err != nil {
		t.Fatalf("CheckPassword clean: %v", err)
	}
	if found {
		t.Fatal("expected clean password not to be found")
	}
}

func TestCheckPasswordAlreadyHashed(t *testing.T) {
	password := "password"
	hash := sha1Upper(password)
	prefix, suffix := hash[:5], hash[5:]

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/range/"+prefix {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, suffix+":1\n")
	}))
	defer srv.Close()

	client := NewClient(false, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithWait(0))

	found, err := client.CheckPassword(strings.ToLower(hash), true)
	if err != nil {
		t.Fatalf("CheckPassword hashed: %v", err)
	}
	if !found {
		t.Fatal("expected hashed password to match")
	}
}

func TestCheckPasswordVerbose(t *testing.T) {
	password := "password"
	hash := sha1Upper(password)
	suffix := hash[5:]

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, suffix+":1\n")
	}))
	defer srv.Close()

	client := NewClient(true, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithWait(0))
	found, err := client.CheckPassword(password, false)
	if err != nil || !found {
		t.Fatalf("verbose match: found=%v err=%v", found, err)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n")
	}))
	defer srv2.Close()

	client2 := NewClient(true, WithBaseURL(srv2.URL), WithHTTPClient(srv2.Client()), WithWait(0))
	found, err = client2.CheckPassword(password, false)
	if err != nil || found {
		t.Fatalf("verbose miss: found=%v err=%v", found, err)
	}
}

func TestCheckPasswordShortHash(t *testing.T) {
	client := NewClient(false, WithWait(0))
	_, err := client.CheckPassword("abcd", true)
	if err == nil {
		t.Fatal("expected error for short hash")
	}
}

func TestCheckPasswordNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := NewClient(true, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithWait(0))
	_, err := client.CheckPassword("password", false)
	if err == nil {
		t.Fatal("expected status error")
	}
}

func TestCheckPasswordNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := NewClient(false, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithWait(0))
	_, err := client.CheckPassword("password", false)
	if err == nil {
		t.Fatal("expected network error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestCheckPasswordBodyReadError(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(errReader{}),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})

	client := NewClient(false,
		WithBaseURL("http://example.invalid"),
		WithHTTPClient(&http.Client{Transport: transport}),
		WithWait(0),
	)
	_, err := client.CheckPassword("password", false)
	if err == nil {
		t.Fatal("expected body read error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewClientDefaultsAndOptions(t *testing.T) {
	c := NewClient(true)
	if c.baseURL != defaultAPI {
		t.Fatalf("baseURL = %s", c.baseURL)
	}
	if c.wait != 100*time.Millisecond {
		t.Fatalf("wait = %v", c.wait)
	}
	if !c.verbose {
		t.Fatal("expected verbose")
	}

	custom := &http.Client{Timeout: time.Second}
	c2 := NewClient(false, WithHTTPClient(nil), WithHTTPClient(custom), WithBaseURL(""), WithBaseURL(defaultAPI+"/"), WithWait(0))
	if c2.client != custom {
		t.Fatal("WithHTTPClient not applied")
	}
	if c2.baseURL != defaultAPI {
		t.Fatalf("trimmed baseURL = %s", c2.baseURL)
	}
	if c2.wait != 0 {
		t.Fatal("WithWait(0) not applied")
	}
}

func TestWaitZeroAndPositive(t *testing.T) {
	c := NewClient(false, WithWait(0))
	start := time.Now()
	c.Wait()
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("Wait(0) should not sleep")
	}

	c2 := NewClient(false, WithWait(20*time.Millisecond))
	start = time.Now()
	c2.Wait()
	if time.Since(start) < 15*time.Millisecond {
		t.Fatal("Wait should sleep")
	}
}
