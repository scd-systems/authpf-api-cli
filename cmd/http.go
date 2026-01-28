// cmd/http.go
package cmd

import (
	"crypto/tls"
	"fmt"
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
