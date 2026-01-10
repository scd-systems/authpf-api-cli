package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication [client]",
	Long:  "Login, logout, and manage authentication tokens",
}

var authLoginCmd = &cobra.Command{
	Use:           "login",
	Short:         "Login to server",
	Long:          "Authenticate against the authpf-api server and obtain a JWT token",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		if serverURL == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: server URL is required\n")
			return fmt.Errorf("")
		}

		if username == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: username is required\n")
			return fmt.Errorf("")
		}

		if password == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: password is required\n")
			return fmt.Errorf("")
		}

		// Perform login
		token, err := performLogin(serverURL, username, password)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Printf("✓ Successfully logged in as %s\n", username)

		// Save token to config file automatically
		if err := saveAuthToken(serverURL, username, token); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: failed to save token: %v\n", err)
			return fmt.Errorf("")
		}
		fmt.Println("✓ Token saved to config file")

		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from server",
	Long:  "Clear stored authentication token",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := clearAuthToken(); err != nil {
			return fmt.Errorf("failed to logout: %w", err)
		}

		fmt.Println("✓ Successfully logged out")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  "Check if you are currently authenticated",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("auth.token")
		username := viper.GetString("auth.username")
		server := viper.GetString("auth.server")

		if token == "" {
			fmt.Println("Authentication Status: ✗ Not authenticated")
			return nil
		}

		fmt.Println("Authentication Status: ✓ Authenticated")
		fmt.Printf("  Username: %s\n", username)
		fmt.Printf("  Server: %s\n", server)

		return nil
	},
}

var authTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage tokens",
	Long:  "View or refresh authentication tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("auth.token")

		if token == "" {
			fmt.Println("No token stored")
			return nil
		}

		fmt.Printf("Current Token: %s\n", token)
		return nil
	},
}

func init() {
	// Login command
	authLoginCmd.Flags().StringP("server", "s", "", "Server URL")
	authLoginCmd.Flags().StringP("username", "u", "", "Username")
	authLoginCmd.Flags().StringP("password", "p", "", "Password")

	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authTokenCmd)
}

// performLogin authenticates against the server and returns a JWT token
func performLogin(serverURL, username, password string) (string, error) {

	fmt.Printf("Authenticating against %s...\n", serverURL)

	// Create login request payload
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login request: %w", err)
	}

	// Create HTTP request
	loginURL := serverURL + "/login"
	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send login request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var loginResp map[string]string
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("failed to parse login response: %w", err)
	}

	token, ok := loginResp["token"]
	if !ok || token == "" {
		return "", fmt.Errorf("no token in response")
	}

	return token, nil
}

// saveAuthToken saves the authentication token to the config file
func saveAuthToken(serverURL, username, token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".authpf-api-cli")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "config.yaml")

	viper.Set("auth.server", serverURL)
	viper.Set("auth.username", username)
	viper.Set("auth.token", token)

	if err := viper.WriteConfigAs(configFile); err != nil {
		return err
	}

	return nil
}

// clearAuthToken removes the stored authentication token
func clearAuthToken() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".authpf-api-cli")
	configFile := filepath.Join(configDir, "config.yaml")

	viper.Set("auth.token", "")
	viper.Set("auth.username", "")
	viper.Set("auth.server", "")

	if err := viper.WriteConfigAs(configFile); err != nil {
		return err
	}

	return nil
}
