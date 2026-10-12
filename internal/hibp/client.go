package hibp

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	colorCyan  = "\033[36m"
	colorReset = "\033[0m"
	userAgent  = "PwnedCheck/1.0"
	defaultAPI = "https://api.pwnedpasswords.com"
)

// Client talks to the Have I Been Pwned Pwned Passwords range API.
type Client struct {
	client  *http.Client
	baseURL string
	verbose bool
	wait    time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for API requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.client = c
		}
	}
}

// WithBaseURL overrides the HIBP API base URL (useful for tests).
func WithBaseURL(baseURL string) Option {
	return func(cl *Client) {
		if baseURL != "" {
			cl.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithWait sets the delay applied by Wait between checks.
func WithWait(d time.Duration) Option {
	return func(cl *Client) {
		cl.wait = d
	}
}

// NewClient returns a Client configured for the public HIBP API.
func NewClient(verbose bool, opts ...Option) *Client {
	cl := &Client{
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: defaultAPI,
		verbose: verbose,
		wait:    100 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(cl)
	}
	return cl
}

// CheckPassword reports whether password (or a precomputed SHA-1 hash) appears
// in the HIBP breach corpus. Only the first 5 hex characters of the SHA-1 hash
// are sent to the API (k-anonymity).
func (c *Client) CheckPassword(password string, alreadyHashed bool) (bool, error) {
	hashString := password
	if !alreadyHashed {
		hashString = hashPassword(password)
	}
	hashString = strings.ToUpper(strings.TrimSpace(hashString))

	if len(hashString) < 5 {
		return false, fmt.Errorf("hash must be at least 5 characters")
	}

	prefix := hashString[:5]
	suffix := hashString[5:]
	url := fmt.Sprintf("%s/range/%s", c.baseURL, prefix)

	if c.verbose {
		fmt.Printf("%s[HIBP REQUEST] GET %s%s\n", colorCyan, url, colorReset)
		fmt.Printf("%s[HIBP REQUEST] Sending prefix: %s  (suffix %s stays local)%s\n", colorCyan, prefix, suffix, colorReset)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if c.verbose {
		fmt.Printf("%s[HIBP RESPONSE] Status: %s%s\n", colorCyan, resp.Status, colorReset)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected API status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read API response: %w", err)
	}

	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
			if c.verbose {
				fmt.Printf("%s[HIBP MATCH] Suffix %s found in response%s\n", colorCyan, suffix, colorReset)
			}
			return true, nil
		}
	}

	if c.verbose {
		fmt.Printf("%s[HIBP MATCH] Suffix %s not found — password clean%s\n", colorCyan, suffix, colorReset)
	}
	return false, nil
}

// Wait pauses briefly between API calls to be polite to HIBP.
func (c *Client) Wait() {
	if c.wait > 0 {
		time.Sleep(c.wait)
	}
}

func hashPassword(password string) string {
	hash := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}
