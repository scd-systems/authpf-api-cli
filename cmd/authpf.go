package cmd

import (
	"bytes"
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

// AuthPFRulesResponse represents the API response with rules and server time
type AuthPFRulesResponse struct {
	Rules      map[string]*AuthPFStatus `json:"rules"`
	ServerTime time.Time                `json:"server_time"`
}

var authpfCmd = &cobra.Command{
	Use:   "authpf",
	Short: "Manage authpf rules [client only]",
	Long:  "Activate, deactivate, and check status of authpf rules",
}

var authpfActivateCmd = &cobra.Command{
	Use:           "activate",
	Short:         "Activate authpf rule",
	Long:          "Activate an authpf rule for a user",
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
		if err := activateAuthPFRule(serverURL, token, authpfUsername, timeout); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Println("✓ AuthPF rule activated successfully")
		return nil
	},
}

var authpfDeactivateCmd = &cobra.Command{
	Use:           "deactivate",
	Short:         "Deactivate authpf rule",
	Long:          "Deactivate an authpf rule for a user",
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
		if err := deactivateAuthPFRule(serverURL, token, authpfUsername, all); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Println("✓ AuthPF rule deactivated successfully")
		return nil
	},
}

var authpfStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Check authpf rule status",
	Long:          "Check the status of an authpf rule",
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

		// Use provided username or fall back to authenticated user
		if authpfUsername == "" {
			authpfUsername = username
		}

		// Call status endpoint
		statusData, err := getAuthPFRuleStatus(serverURL, token, authpfUsername)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		// Check if status is nil (no active rule)
		if statusData == nil {
			fmt.Println("✗ AuthPF rule status: inactive")
			fmt.Println("  No active rule found for this user")
			return nil
		}

		// Parse response as AuthPFRulesResponse
		apiResponse, ok := statusData.(*AuthPFRulesResponse)
		if !ok {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: invalid response format\n")
			return fmt.Errorf("")
		}

		// Check if rules map is empty
		if len(apiResponse.Rules) == 0 {
			fmt.Println("✗ AuthPF rule status: inactive")
			fmt.Println("  No active rule found for this user")
			return nil
		}

		// Get the first (and usually only) rule for the user
		var status *AuthPFStatus
		for _, rule := range apiResponse.Rules {
			status = rule
			break
		}

		if status == nil {
			fmt.Println("✗ AuthPF rule status: inactive")
			fmt.Println("  No active rule found for this user")
			return nil
		}

		fmt.Println(formatAuthPFStatus(status, apiResponse.ServerTime))
		return nil
	},
}

func init() {
	// Activate command
	authpfActivateCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")
	authpfActivateCmd.Flags().StringP("timeout", "t", "", "Timeout duration (e.g., 1h, 30m)")

	// Deactivate command
	authpfDeactivateCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")
	authpfDeactivateCmd.Flags().BoolP("all", "a", false, "Deactivate all rules")

	// Status command
	authpfStatusCmd.Flags().StringP("username", "u", "", "Username (optional, defaults to authenticated user)")

	authpfCmd.AddCommand(authpfActivateCmd)
	authpfCmd.AddCommand(authpfDeactivateCmd)
	authpfCmd.AddCommand(authpfStatusCmd)
}

// activateAuthPFRule sends a POST request to activate an authpf rule
func activateAuthPFRule(serverURL, token, username, timeout string) error {
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
	client := &http.Client{}
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

// deactivateAuthPFRule sends a DELETE request to deactivate an authpf rule
func deactivateAuthPFRule(serverURL, token, username string, all bool) error {
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
	client := &http.Client{}
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

// getAuthPFRuleStatus sends a GET request to check authpf rule status
func getAuthPFRuleStatus(serverURL, token, username string) (interface{}, error) {
	// Build query parameters
	params := url.Values{}
	if username != "" {
		params.Add("authpf_username", username)
	}

	// Build URL
	endpoint := serverURL + "/api/v1/authpf/activate"
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
	client := &http.Client{}
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

	// Parse response into AuthPFRulesResponse
	var apiResponse AuthPFRulesResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Return the response with server time for client-side calculations
	return &apiResponse, nil
}

// formatAuthPFStatus formats the status for display
func formatAuthPFStatus(status *AuthPFStatus, serverTime time.Time) string {
	// Format the output
	output := fmt.Sprintf("✓ AuthPF rule status: active\n")
	output += fmt.Sprintf("  Username: %s\n", status.Username)
	output += fmt.Sprintf("  UserIP: %s\n", status.UserIP)
	output += fmt.Sprintf("  UserID: %d\n", status.UserID)
	output += fmt.Sprintf("  Timeout: %s\n", status.Timeout)

	// Format expire_at timestamp if available
	if !status.ExpiresAt.IsZero() {
		// Use server time for accurate calculation
		timeRemaining := status.ExpiresAt.Sub(serverTime)

		output += fmt.Sprintf("  Rules Expire At: %s\n", status.ExpiresAt.Format("2006-01-02 03:04 PM"))
		output += fmt.Sprintf("  Rules Expire In: %s", formatDuration(timeRemaining))
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
