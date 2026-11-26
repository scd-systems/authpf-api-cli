// cmd/http.go
package cmd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type HTTPClientConfig struct {
	Timeout    time.Duration
	CACertPath string
	Insecure   bool
	UseHTTPS   bool
}

// maxResponseBytes bounds how much of a response the client buffers. An endpoint the user
// does not trust must not be able to drive the client's memory or flood the terminal with
// a body. 8 MB is about four times what a 10000 anchor list needs, raise it here if a
// gateway ever outgrows that.
const maxResponseBytes = 8 << 20

func getURLScheme(serverAddr string) string {
	parsedURL, err := url.Parse(serverAddr)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsedURL.Scheme)
}

func DefaultHTTPConfig() HTTPClientConfig {
	var useHTTPS bool
	if getURLScheme(viper.GetString(VIPER_PARAM_SERVER)) == "https" {
		useHTTPS = true
	}
	return HTTPClientConfig{
		Timeout:    30 * time.Second,
		CACertPath: viper.GetString(VIPER_PARAM_CACERT),
		Insecure:   viper.GetBool(VIPER_PARAM_INSECURE),
		UseHTTPS:   useHTTPS,
	}
}

func NewHTTPClient(config HTTPClientConfig) (*http.Client, error) {
	client := &http.Client{
		Timeout: config.Timeout,
	}
	if !config.UseHTTPS {
		return client, nil
	}
	if config.Insecure {
		// Skip certificate verification (insecure mode)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else if config.CACertPath != "" {
		tlsConfig, err := createTLSConfig(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return client, nil
}

func NewHTTPClientWithDefaults() (*http.Client, error) {
	return NewHTTPClient(DefaultHTTPConfig())
}

func NewHTTPClientWithTimeout(timeout time.Duration) (*http.Client, error) {
	config := DefaultHTTPConfig()
	config.Timeout = timeout
	return NewHTTPClient(config)
}

func sendRequest(url string, method string, data ...byte) ([]byte, int, error) {
	body, statusCode, _, err := sendRequestWithServerTime(url, method, data...)
	return body, statusCode, err
}

// sendRequestWithServerTime is sendRequest plus the server's own clock as seen in the
// Date header of its response. Token and anchor expiry must be measured against that
// clock, because the client clock is the one thing we cannot assume to be right.
func sendRequestWithServerTime(url string, method string, data ...byte) ([]byte, int, time.Time, error) {
	// Create request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, http.StatusInternalServerError, time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+viper.GetString(VIPER_PARAM_AUTHPF_TOKEN))

	// Send request
	client, err := NewHTTPClientWithDefaults()
	if err != nil {
		return nil, http.StatusInternalServerError, time.Time{}, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, time.Time{}, fmt.Errorf("failed to send request: %w", err)
	}
	// body is read below: a close error cannot reach the caller
	defer func() { _ = resp.Body.Close() }()

	// Read response, one byte past the limit to tell a full body from a truncated one
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, http.StatusInternalServerError, time.Time{}, fmt.Errorf("failed to read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, http.StatusInternalServerError, time.Time{},
			fmt.Errorf("response exceeds the %d MB limit", maxResponseBytes>>20)
	}

	return body, resp.StatusCode, responseServerTime(resp), nil
}

// responseServerTime reads the server clock from a response, or the zero time when the
// server sent no usable Date header.
func responseServerTime(resp *http.Response) time.Time {
	// shortcut: the HTTP Date header has 1 second resolution and ignores the request
	// round trip, both far below the tolerance clock skew is reported at.
	raw := resp.Header.Get("Date")
	if raw == "" {
		return time.Time{}
	}

	serverTime, err := http.ParseTime(raw)
	if err != nil {
		return time.Time{}
	}

	return serverTime.UTC()
}
