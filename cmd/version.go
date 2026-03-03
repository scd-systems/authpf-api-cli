package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/viper"
)

const API_VERSION = "1.2"

// serverInfo represents the JSON response from GET /info
type serverInfo struct {
	Version     string `json:"version"`
	API_Version string `json:"API"`
}

// versionInfo represents the version information output
type versionInfo struct {
	CLIVersion       string `json:"client_version"`
	APIVersion       string `json:"client_supported_api"`
	ServerVersion    string `json:"server_version,omitempty"`
	ServerAPIVersion string `json:"server_api_version,omitempty"`
}

// getServerVersion fetches the version string from the server's /info endpoint.
func getServerInfo(config HTTPClientConfig) (*serverInfo, error) {
	var info serverInfo

	endpoint := strings.TrimRight(viper.GetString(VIPER_PARAM_SERVER), "/") + ENDPOINT_INFO

	response, statusCode, err := sendRequest(endpoint, METHOD_ENDPOINT_INFO)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("server version request failed with status %d", statusCode)
	}

	if err := json.NewDecoder(bytes.NewReader(response)).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode server info response: %w", err)
	}
	if info.API_Version == "" {
		return nil, fmt.Errorf("server did not provide an API version")
	}
	return &info, nil
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
func checkAPIVersionCompatibility() error {
	serverInfo, err := getServerInfo(DefaultHTTPConfig())
	if err != nil {
		return err
	}

	// The variable 'version' is defined in cmd/root.go and holds the CLI version.
	return compareAPIVersions(API_VERSION, serverInfo.API_Version)
}

// DisplayVersionInfo displays version information in JSON format.
// It includes the CLI version and API version.
func DisplayVersionInfo(cliVersion string) error {
	info := versionInfo{
		CLIVersion: cliVersion,
		APIVersion: API_VERSION,
	}

	// Try to fetch server information, but silently ignore errors
	serverInfo, err := getServerInfo(DefaultHTTPConfig())
	if err == nil {
		info.ServerVersion = serverInfo.Version
		info.ServerAPIVersion = serverInfo.API_Version
	}

	// Marshal to JSON and print
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal version info to JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}
