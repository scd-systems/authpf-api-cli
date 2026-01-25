package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AuthPFStatus represents the status response from the API
type AuthPFStatus struct {
	Username  string    `json:"username"`
	UserIP    string    `json:"user_ip"`
	UserID    int       `json:"user_id"`
	Timeout   string    `json:"timeout,omitempty"`
	ExpiresAt time.Time `json:"expire_at"`
}

// AuthPFAnchorsResponse represents the API response with anchor and server time
type AuthPFAnchorsResponse struct {
	Anchors    map[string]*AuthPFStatus
	ServerTime time.Time
}

var authpfCmd = &cobra.Command{
	Use:   "authpf",
	Short: "Manage authpf anchors [client only]",
	Long:  "Activate, deactivate, and check status of authpf anchors",
}

var authpfActivateCmd = &cobra.Command{
	Use:           "activate",
	Short:         "Activate authpf anchor",
	Long:          "Activate an authpf anchor for a user",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("auth.server")
		token := viper.GetString("auth.token")
		username := viper.GetString("auth.username")

		if serverURL == "" || token == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: not authenticated. Please login first\n")
			return fmt.Errorf("")
		}

		// Get optional parameters
		authpfUsername, _ := cmd.Flags().GetString("username")
		timeout, _ := cmd.Flags().GetString("timeout")

		// Use provided username or fall back to authenticated user
		if authpfUsername == "" {
			authpfUsername = username
		}

		// Call activate endpoint
		if err := activateAuthPFAnchor(serverURL, token, authpfUsername, timeout); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Println("✅ AuthPF anchor activated successfully")
		return nil
	},
}

var authpfDeactivateCmd = &cobra.Command{
	Use:           "deactivate",
	Short:         "Deactivate authpf anchor",
	Long:          "Deactivate an authpf anchor for a user",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("auth.server")
		token := viper.GetString("auth.token")
		username := viper.GetString("auth.username")

		if serverURL == "" || token == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: not authenticated. Please login first\n")
			return fmt.Errorf("")
		}

		// Get optional parameters
		authpfUsername, _ := cmd.Flags().GetString("username")
		all, _ := cmd.Flags().GetBool("all")

		// Use provided username or fall back to authenticated user
		if authpfUsername == "" {
			authpfUsername = username
		}

		// Call deactivate endpoint
		if err := deactivateAuthPFAnchor(serverURL, token, authpfUsername, all); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Println("✅ AuthPF anchor deactivated successfully")
		return nil
	},
}

var authpfStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Check authpf anchor status",
	Long:          "Check the status of an authpf anchor",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("auth.server")
		token := viper.GetString("auth.token")
		username := viper.GetString("auth.username")

		if serverURL == "" || token == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: not authenticated. Please login first\n")
			return fmt.Errorf("")
		}

		// Get optional parameters
		authpfUsername, _ := cmd.Flags().GetString("username")
		all, _ := cmd.Flags().GetBool("all")

		// Use provided username or fall back to authenticated user
		if authpfUsername == "" {
			authpfUsername = username
		}

		// Call status endpoint
		statusData, err := getAuthPFAnchorStatus(serverURL, token, authpfUsername, all)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		// Check if status is nil (no active anchor)
		if statusData == nil {
			fmt.Println("❌ AuthPF anchor status: inactive")
			fmt.Println("  No active anchor found")
			return nil
		}

		// Parse response as AuthPFAnchorsResponse
		apiResponse, ok := statusData.(*AuthPFAnchorsResponse)
		if !ok {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: invalid response format\n")
			return fmt.Errorf("")
		}

		// Check if anchors map is empty
		if len(apiResponse.Anchors) == 0 {
			fmt.Println("❌ AuthPF anchor status: inactive")
			fmt.Println("  No active anchor found")
			return nil
		}

		// If --all flag is set, display all anchors
		if all {
			fmt.Println("✅ AuthPF anchor status: active")
			fmt.Printf("  Total active anchors: %d\n\n", len(apiResponse.Anchors))
			for key, status := range apiResponse.Anchors {
				fmt.Printf("  Anchor: %s\n", key)
				fmt.Println(formatAuthPFStatusDetailed(status, apiResponse.ServerTime))
			}
		} else {
			// Get the first (and usually only) anchor for the user
			var status *AuthPFStatus
			for _, anchor := range apiResponse.Anchors {
				status = anchor
				break
			}

			if status == nil {
				fmt.Println("❌ AuthPF status: inactive")
				fmt.Println("  No active anchors found")
				return nil
			}

			fmt.Println(formatAuthPFStatus(status, apiResponse.ServerTime))
		}
		return nil
	},
}

func init() {
	// Activate command
	authpfActivateCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")
	authpfActivateCmd.Flags().StringP("timeout", "t", "", "Timeout duration (e.g., 1h, 30m)")

	// Deactivate command
	authpfDeactivateCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")
	authpfDeactivateCmd.Flags().BoolP("all", "a", false, "Deactivate all anchors")

	// Status command
	authpfStatusCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")
	authpfStatusCmd.Flags().BoolP("all", "a", false, "Get status for all anchors")

	authpfCmd.AddCommand(authpfActivateCmd)
	authpfCmd.AddCommand(authpfDeactivateCmd)
	authpfCmd.AddCommand(authpfStatusCmd)
}

// getHTTPClientWithTLS creates an HTTP client with optional CA certificate or insecure mode
func getHTTPClientWithTLS() (*http.Client, error) {
	caCertPath := viper.GetString("auth.ca_cert")
	insecure := viper.GetBool("auth.insecure")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if insecure {
		// Skip certificate verification (insecure mode)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else if caCertPath != "" {
		tlsConfig, err := createTLSConfig(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return client, nil
}

// activateAuthPFAnchor sends a POST request to activate an authpf anchor
func activateAuthPFAnchor(serverURL, token, username, timeout string) error {
	// Build query parameters
	params := url.Values{}
	if username != "" {
		params.Add("authpf_username", username)
	}
	if timeout != "" {
		params.Add("timeout", timeout)
	}

	// Build URL
	endpoint := serverURL + "/api/v1/authpf/activate"
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	// Create request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Send request
	client, err := getHTTPClientWithTLS()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("activate failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// deactivateAuthPFAnchor sends a DELETE request to deactivate an authpf anchor
func deactivateAuthPFAnchor(serverURL, token, username string, all bool) error {
	// Determine endpoint
	endpoint := serverURL + "/api/v1/authpf/activate"
	if all {
		endpoint = serverURL + "/api/v1/authpf/all"
	}

	// Build query parameters
	params := url.Values{}
	if username != "" && !all {
		params.Add("authpf_username", username)
	}

	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	// Create request
	req, err := http.NewRequest("DELETE", endpoint, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Send request
	client, err := getHTTPClientWithTLS()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deactivate failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getAuthPFAnchorStatus sends a GET request to check AuthPF anchor status
func getAuthPFAnchorStatus(serverURL, token, username string, all bool) (interface{}, error) {
	// Build query parameters
	params := url.Values{}
	if username != "" {
		params.Add("authpf_username", username)
	}

	// Build URL
	endpoint := serverURL + "/api/v1/authpf/activate"
	if all {
		endpoint = serverURL + "/api/v1/authpf/all"
	}

	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	// Create request
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)

	// Send request
	client, err := getHTTPClientWithTLS()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status check failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response into AuthPFAnchorsResponse
	var apiResponse AuthPFAnchorsResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Return the response with server time for client-side calculations
	return &apiResponse, nil
}

// formatAuthPFStatus formats the status for display
func formatAuthPFStatus(status *AuthPFStatus, serverTime time.Time) string {
	// Format the output
	output := "✅ AuthPF anchor status: active\n"
	output += fmt.Sprintf("  Username: %s\n", status.Username)
	output += fmt.Sprintf("  UserIP: %s\n", status.UserIP)
	output += fmt.Sprintf("  UserID: %d\n", status.UserID)
	output += fmt.Sprintf("  Timeout: %s\n", status.Timeout)

	// Format expire_at timestamp if available
	if !status.ExpiresAt.IsZero() {
		// Use server time for accurate calculation
		timeRemaining := status.ExpiresAt.Sub(serverTime)

		output += fmt.Sprintf("  Expire At: %s\n", status.ExpiresAt.Format("2006-01-02 03:04 PM"))
		output += fmt.Sprintf("  Expire In: %s", formatDuration(timeRemaining))
	}

	return output
}

// formatAuthPFStatusDetailed formats the status for display in a list (with extra indentation)
func formatAuthPFStatusDetailed(status *AuthPFStatus, serverTime time.Time) string {
	// Format the output with extra indentation for list display
	output := fmt.Sprintf("    Username: %s\n", status.Username)
	output += fmt.Sprintf("    UserIP: %s\n", status.UserIP)
	output += fmt.Sprintf("    UserID: %d\n", status.UserID)
	output += fmt.Sprintf("    Timeout: %s\n", status.Timeout)

	// Format expire_at timestamp if available
	if !status.ExpiresAt.IsZero() {
		// Use server time for accurate calculation
		timeRemaining := status.ExpiresAt.Sub(serverTime)

		output += fmt.Sprintf("    Expire At: %s\n", status.ExpiresAt.Format("2006-01-02 03:04 PM"))
		output += fmt.Sprintf("    Expire In: %s\n", formatDuration(timeRemaining))
	}

	return output
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired (server time difference)"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
