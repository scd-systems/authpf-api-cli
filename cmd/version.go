package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// serverInfo represents the JSON response from GET /info
type serverInfo struct {
	Version     string `json:"version"`
	API_Version string `json:"API"`
}

// getServerVersion fetches the version string from the server's /info endpoint.
func getServerAPIVersion(serverURL string) (string, error) {
	// Build the URL for the /info endpoint
	endpoint := strings.TrimRight(serverURL, "/") + ENDPOINT_INFO

	// Use the same HTTP client configuration as other requests
	client, err := getHTTPClientWithTLS()
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client: %w", err)
	}

	req, err := http.NewRequest(METHOD_ENDPOINT_INFO, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server version request failed with status %d", resp.StatusCode)
	}

	var info serverInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode server API version response: %w", err)
	}
	if info.API_Version == "" {
		return "", fmt.Errorf("server did not provide an API version")
	}
	return info.API_Version, nil
}

// parseVersion splits a semantic version string (e.g., "2.1.3") into major, minor, and patch integers.
func parseVersion(v string) (int, int, error) {
	var major, minor int
	n, err := fmt.Sscanf(v, "%d.%d", &major, &minor)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("invalid version format: %s", v)
	}
	return major, minor, nil
}

// compareVersions ensures that the CLI version and server version have the same major and minor numbers.
// It returns nil if compatible, otherwise an error describing the incompatibility.
func compareAPIVersions(cliVersion, serverVersion string) error {
	cliMajor, cliMinor, err := parseVersion(cliVersion)
	if err != nil {
		return fmt.Errorf("invalid CLI version: %w", err)
	}
	srvMajor, srvMinor, err := parseVersion(serverVersion)
	if err != nil {
		return fmt.Errorf("invalid server version: %w", err)
	}
	if cliMajor != srvMajor {
		return fmt.Errorf("major version mismatch: CLI %d, server %d", cliMajor, srvMajor)
	}
	if cliMinor != srvMinor {
		return fmt.Errorf("minor version mismatch: CLI %d.%d, server %d.%d", cliMajor, cliMinor, srvMajor, srvMinor)
	}
	return nil
}

// checkVersionCompatibility fetches the server version and validates it against the CLI version.
func checkAPIVersionCompatibility(serverURL string) error {
	srvVer, err := getServerAPIVersion(serverURL)
	if err != nil {
		return err
	}
	// The variable 'version' is defined in cmd/root.go and holds the CLI version.
	return compareAPIVersions(API_VERSION, srvVer)
}
