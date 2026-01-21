package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v3"
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
		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		insecure, _ := cmd.Flags().GetBool("insecure")

		// Try to load credentials from environment variables first
		if serverURL == "" {
			envParam := os.Getenv("AUTHPF_API_SERVER")
			if envParam == "" {
				serverURL = viper.GetString("auth.server")
			} else {
				serverURL = envParam
			}
		}
		if username == "" {
			envParam := os.Getenv("AUTHPF_API_USERNAME")
			if envParam == "" {
				username = viper.GetString("auth.username")
			} else {
				username = envParam
			}
		}
		if password == "" {
			envParam := os.Getenv("AUTHPF_API_PASSWORD")
			if envParam == "" {
				password = viper.GetString("auth.username")
			} else {
				password = envParam
			}
		}
		if caCertPath == "" {
			envParam := os.Getenv("AUTHPF_API_CACERT")
			if envParam == "" {
				caCertPath = viper.GetString("auth.username")
			} else {
				caCertPath = envParam
			}
		}
		if insecure == false {
			envParam := os.Getenv("AUTHPF_API_INSECURE")
			if envParam == "" {
				insecure = viper.GetBool("auth.insecure")
			} else {
				if strings.ToLower(envParam) == "true" {
					insecure = true
				}
			}
		}

		// hash password if set
		if len(password) > 0 {
			pwHash, err := createSha256(password)
			if err != nil {
				return err
			}
			password = pwHash
		}

		// Try to load credentials from file if not provided via flags or environment variables
		if username == "" || password == "" {
			creds, err := loadCredentialsFromFile()
			if err == nil {
				if username == "" {
					username = creds.Username
				}
				if password == "" {
					password = creds.Password
				}
			}
		}

		if serverURL == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "❌ Error: server URL is required\n")
			return fmt.Errorf("")
		}

		if username == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "❌ Error: username is required\n")
			return fmt.Errorf("")
		}

		if password == "" {
			fmt.Fprintf(cmd.OutOrStderr(), "❌ Error: password is required\n")
			return fmt.Errorf("")
		}

		// Perform login
		token, err := performLogin(serverURL, username, password, caCertPath, insecure)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "❌ Error: %v\n", err)
			return fmt.Errorf("")
		}

		fmt.Printf("✅ Successfully logged in as %s\n", username)

		// Save token and auth settings to config file automatically
		if err := saveAuthToken(serverURL, username, token, caCertPath, insecure); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "❌ Error: failed to save token: %v\n", err)
			return fmt.Errorf("")
		}
		fmt.Println("✅ Token saved to config file")

		// Save credentials to credentials file if provided via flags
		if username != "" && password != "" {
			if err := saveCredentialsToFile(username, password); err != nil {
				fmt.Fprintf(cmd.OutOrStderr(), "⚠️ Warning: failed to save credentials file: %v\n", err)
				// Don't fail the login if credentials file save fails
			} else {
				fmt.Println("✅ Credentials saved to credentials file")
			}
		}

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

		fmt.Println("✅ Successfully logged out")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check authentication status",
	Long:  "Check if you are currently authenticated and validate token against server",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("auth.token")
		// username := viper.GetString("auth.username")
		server := viper.GetString("auth.server")
		caCertPath := viper.GetString("auth.ca_cert")
		insecure := viper.GetBool("auth.insecure")

		if token == "" {
			fmt.Println("Authentication Status: ❌ Not authenticated")
			return nil
		}

		// Validate token against server
		isValid, expiresAt, err := validateTokenAgainstServer(server, token, caCertPath, insecure)
		if err != nil {
			fmt.Printf("  Token Validation: ⚠️ Warning - %v\n", err)
		} else if isValid {
			fmt.Println("  Token Validation: ✅ Valid")
			if !expiresAt.IsZero() {
				duration := time.Until(expiresAt)
				if duration > 0 {
					fmt.Printf("  Expires in: %s\n", formatDuration(duration))
					fmt.Printf("  Expires at: %s\n", expiresAt.Format("2006-01-02 15:04:05 MST"))
				} else {
					fmt.Println("  Token Status: ❌ Expired")
				}
			}
		} else {
			fmt.Println("  Token Validation: ❌ Invalid")
		}

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
	authLoginCmd.Flags().StringP("ca-cert", "c", "", "Path to CA certificate file for HTTPS verification")
	authLoginCmd.Flags().BoolP("insecure", "i", false, "Skip HTTPS certificate verification (insecure, use with caution)")

	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authTokenCmd)
}

// performLogin authenticates against the server and returns a JWT token
func performLogin(serverURL, username, password, caCertPath string, insecure bool) (string, error) {

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

	// Create HTTP client with optional CA certificate or insecure mode
	client := &http.Client{}
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
			return "", fmt.Errorf("failed to configure TLS: %w", err)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	// Send request
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

// saveAuthToken saves the authentication token and auth settings to the config file
func saveAuthToken(serverURL, username, token, caCertPath string, insecure bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".authpf-api-cli")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "config.yaml")

	// Convert caCertPath to absolute path if provided
	if caCertPath != "" {
		absCertPath, err := filepath.Abs(caCertPath)
		if err != nil {
			return fmt.Errorf("failed to convert CA cert path to absolute: %w", err)
		}
		caCertPath = absCertPath
	}

	viper.Set("auth.server", serverURL)
	viper.Set("auth.token", token)
	viper.Set("auth.ca_cert", caCertPath)
	viper.Set("auth.insecure", insecure)

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

// Credentials represents the structure of the credentials file
type Credentials struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// loadCredentialsFromFile loads credentials from the credentials file
// The file is expected to be in the same directory as the config file
// with the name "credentials.yaml" and permissions 0600
func loadCredentialsFromFile() (*Credentials, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".authpf-api-cli")
	credentialsFile := filepath.Join(configDir, "credentials.yaml")

	// Check if file exists
	if _, err := os.Stat(credentialsFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("credentials file not found at %s", credentialsFile)
	}

	// Check file permissions (should be 0600)
	fileInfo, err := os.Stat(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to stat credentials file: %w", err)
	}

	mode := fileInfo.Mode().Perm()
	if mode != 0600 {
		return nil, fmt.Errorf("credentials file has incorrect permissions: %o (expected 0600)", mode)
	}

	// Read file
	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	// Parse YAML
	var creds Credentials
	if err := yaml.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %w", err)
	}

	// Validate credentials
	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("credentials file is missing required fields (username, password)")
	}

	return &creds, nil
}

// createTLSConfig creates a TLS configuration with a custom CA certificate
func createTLSConfig(caCertPath string) (*tls.Config, error) {
	// Read the CA certificate file
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
	}

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	return tlsConfig, nil
}

// saveCredentialsToFile saves credentials to the credentials file with 0600 permissions
func saveCredentialsToFile(username, password string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".authpf-api-cli")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	credentialsFile := filepath.Join(configDir, "credentials.yaml")

	// Create credentials structure
	creds := Credentials{
		Username: username,
		Password: password,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Write file with 0600 permissions
	if err := os.WriteFile(credentialsFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	return nil
}

// validateTokenAgainstServer validates the token against the server and returns expiration time
func validateTokenAgainstServer(serverURL, token, caCertPath string, insecure bool) (bool, time.Time, error) {
	// First, try to extract expiration from JWT claims without verification
	expiresAt, err := extractTokenExpiration(token)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	// Create HTTP request to validate token against server
	validateURL := serverURL + "/api/v1/authpf/activate"
	req, err := http.NewRequest("GET", validateURL, nil)
	if err != nil {
		return false, expiresAt, fmt.Errorf("failed to create validation request: %w", err)
	}

	// Set authorization header with Bearer token
	req.Header.Set("Authorization", "Bearer "+token)

	// Create HTTP client with optional CA certificate or insecure mode
	client := &http.Client{}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else if caCertPath != "" {
		tlsConfig, err := createTLSConfig(caCertPath)
		if err != nil {
			return false, expiresAt, fmt.Errorf("failed to configure TLS: %w", err)
		}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return false, expiresAt, fmt.Errorf("failed to send validation request: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode == http.StatusOK {
		return true, expiresAt, nil
	} else if resp.StatusCode == http.StatusUnauthorized {
		return false, expiresAt, nil
	}

	// Read response body for error details
	body, _ := io.ReadAll(resp.Body)
	return false, expiresAt, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
}

// extractTokenExpiration extracts the expiration time from a JWT token without verification
func extractTokenExpiration(tokenString string) (time.Time, error) {
	// Parse token without verification (we only need the claims)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &jwt.RegisteredClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid token claims")
	}

	// Return expiration time
	if claims.ExpiresAt != nil {
		return claims.ExpiresAt.Time, nil
	}

	return time.Time{}, nil
}
