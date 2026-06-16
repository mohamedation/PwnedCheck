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
)

type Client struct {
	client  *http.Client
	verbose bool
}

func NewClient(verbose bool) *Client {
	return &Client{
		client:  &http.Client{Timeout: 10 * time.Second},
		verbose: verbose,
	}
}

func (c *Client) CheckPassword(password string, alreadyHashed bool) (bool, error) {
	hashString := password
	if !alreadyHashed {
		hashString = hashPassword(password)
	}

	if len(hashString) < 5 {
		return false, fmt.Errorf("hash must be at least 5 characters")
	}

	prefix := hashString[:5]
	suffix := hashString[5:]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

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
		if len(parts) == 2 && parts[0] == suffix {
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

// to be nice
func (c *Client) Wait() {
	time.Sleep(100 * time.Millisecond)
}

func hashPassword(password string) string {
	hash := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}
