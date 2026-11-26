package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
		// hash password if flag used
		if DetermineValueSource(cmd, "password", "AUTHPF_API_PASSWORD", VIPER_PARAM_PASSWORD) == "FLAG" {
			pw, _ := cmd.Flags().GetString("password")
			pwHash, err := createSha256(pw)
			if err != nil {
				return err
			}
			viper.Set(VIPER_PARAM_PASSWORD, pwHash)
		}

		// Try to load credentials from file if not provided via flags or environment variables
		if viper.GetString(VIPER_PARAM_USERNAME) == "" || viper.GetString(VIPER_PARAM_PASSWORD) == "" {
			creds, err := loadCredentialsFromFile()
			if err == nil {
				if viper.GetString(VIPER_PARAM_USERNAME) == "" {
					viper.Set(VIPER_PARAM_USERNAME, creds.Username)
				}
				if viper.GetString(VIPER_PARAM_PASSWORD) == "" {
					viper.Set(VIPER_PARAM_PASSWORD, creds.Password)
				}
			}
		}

		if err := validateUsername(viper.GetString(VIPER_PARAM_USERNAME)); err != nil {
			return err
		}
		if err := validatePassword(viper.GetString(VIPER_PARAM_PASSWORD)); err != nil {
			return err
		}

		if viper.GetString(VIPER_PARAM_SERVER) == "" {
			return fmt.Errorf("server URL is required")
		}

		if viper.GetString(VIPER_PARAM_USERNAME) == "" {
			return fmt.Errorf("username is required")
		}

		if viper.GetString(VIPER_PARAM_PASSWORD) == "" {
			return fmt.Errorf("password is required")
		}

		// Perform login
		token, loginServerTime, err := performLogin()
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		viper.Set(VIPER_PARAM_AUTHPF_TOKEN, token)

		fmt.Printf("✅ Successfully logged in as %s\n", viper.GetString(VIPER_PARAM_USERNAME))

		// Save token and auth settings to config file automatically
		if err := saveAuthToken(); err != nil {
			return fmt.Errorf("failed to save token: %v", err)
		}
		fmt.Println("✅ Token saved to config file")

		// Save credentials to credentials file if provided via flags
		if viper.GetString(VIPER_PARAM_USERNAME) != "" && viper.GetString(VIPER_PARAM_PASSWORD) != "" {
			if err := saveCredentialsToFile(viper.GetString(VIPER_PARAM_USERNAME), viper.GetString(VIPER_PARAM_PASSWORD)); err != nil {
				// Don't fail the login if credentials file save fails.
				// Stderr is the reporting channel itself, so there is nowhere to report a write error.
				_, _ = fmt.Fprintf(cmd.OutOrStderr(), "⚠️ Warning: failed to save credentials file: %v\n", err)
			} else {
				fmt.Println("✅ Credentials saved to credentials file")
			}
		}

		// The server issued this token itself, so it is valid by definition. Only its
		// remaining lifetime and a possible clock difference are worth showing here.
		expiresAt, _ := extractTokenExpiration(token)
		tokenValidation{valid: true, expiresAt: expiresAt, serverTime: loginServerTime}.printValid()

		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:           "logout",
	Short:         "Logout from server",
	Long:          "Clear stored authentication token",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := clearAuthToken(); err != nil {
			return fmt.Errorf("failed to logout: %w", err)
		}

		fmt.Println("✅ Successfully logged out")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Check authentication status",
	Long:          "Check if you are currently authenticated and validate token against server",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.GetString(VIPER_PARAM_AUTHPF_TOKEN) == "" {
			// Exit 1, so `auth status && <something>` cannot succeed without a token.
			return errors.New("not authenticated, please run auth login")
		}

		// Validate token against server
		validation, err := validateTokenAgainstServer()
		if err != nil {
			return fmt.Errorf("token validation: %w", err)
		}
		if !validation.valid {
			return errors.New("token rejected by server, please run auth login")
		}

		validation.printValid()
		return nil
	},
}

var authTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage tokens",
	Long:  "View or refresh authentication tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("api.token")

		if token == "" {
			fmt.Println("No token stored")
			return nil
		}

		// shortcut: a server may hand out a token shorter than the 10 characters shown,
		// and JWTs are ASCII, so a byte cut here can only ever land on a placeholder.
		shown := token
		if len(shown) > 10 {
			shown = shown[:10]
		}
		fmt.Printf("Current Token: %s....\n", sanitizeDisplay(shown))
		return nil
	},
}

func init() {
	authLoginCmd.Flags().StringP("server", "s", "", "Server URL")
	authLoginCmd.Flags().StringP("username", "u", "", "Username")
	authLoginCmd.Flags().StringP("password", "p", "", "Password")
	authLoginCmd.Flags().StringP("cacert", "c", "", "Path to CA certificate file for HTTPS verification")
	authLoginCmd.Flags().BoolP("insecure", "i", false, "Skip HTTPS certificate verification (insecure, use with caution)")

	if err := viper.BindPFlag(VIPER_PARAM_SERVER, authLoginCmd.Flags().Lookup("server")); err != nil {
		log.Fatal(err.Error())
	}
	if err := viper.BindPFlag(VIPER_PARAM_USERNAME, authLoginCmd.Flags().Lookup("username")); err != nil {
		log.Fatal(err.Error())
	}
	if err := viper.BindPFlag(VIPER_PARAM_PASSWORD, authLoginCmd.Flags().Lookup("password")); err != nil {
		log.Fatal(err.Error())
	}
	if err := viper.BindPFlag(VIPER_PARAM_CACERT, authLoginCmd.Flags().Lookup("cacert")); err != nil {
		log.Fatal(err.Error())
	}
	if err := viper.BindPFlag(VIPER_PARAM_INSECURE, authLoginCmd.Flags().Lookup("insecure")); err != nil {
		log.Fatal(err.Error())
	}

	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authTokenCmd)
}

func DetermineValueSource(cmd *cobra.Command, flagName, envKey, configKey string) string {
	if flag := cmd.Flags().Lookup(flagName); flag != nil && flag.Changed {
		return "FLAG"
	}

	if _, exists := os.LookupEnv(envKey); exists {
		return "ENV"
	}

	if viper.IsSet(configKey) {
		return "CONFIG"
	}

	return "DEFAULT"
}

// loginWithStoredCredentials refreshes the token from configured or saved credentials.
func loginWithStoredCredentials() error {
	if viper.GetString(VIPER_PARAM_USERNAME) == "" || viper.GetString(VIPER_PARAM_PASSWORD) == "" {
		creds, err := loadCredentialsFromFile()
		if err != nil {
			return fmt.Errorf("credentials unavailable; run auth login: %w", err)
		}
		if viper.GetString(VIPER_PARAM_USERNAME) == "" {
			viper.Set(VIPER_PARAM_USERNAME, creds.Username)
		}
		if viper.GetString(VIPER_PARAM_PASSWORD) == "" {
			viper.Set(VIPER_PARAM_PASSWORD, creds.Password)
		}
	}

	if err := validateUsername(viper.GetString(VIPER_PARAM_USERNAME)); err != nil {
		return err
	}
	if err := validatePassword(viper.GetString(VIPER_PARAM_PASSWORD)); err != nil {
		return err
	}

	token, _, err := performLogin()
	if err != nil {
		return err
	}
	viper.Set(VIPER_PARAM_AUTHPF_TOKEN, token)
	return saveAuthToken()
}

// performLogin authenticates against the server and returns a JWT token together with
// the server clock taken from the response.
func performLogin() (string, time.Time, error) {

	// Verify version compatibility before attempting login
	if err := checkAPIVersionCompatibility(); err != nil {
		return "", time.Time{}, fmt.Errorf("version compatibility check failed: %w", err)
	}
	fmt.Printf("Authenticating against %s...\n", viper.GetString(VIPER_PARAM_SERVER))

	// Create login request payload
	loginReq := map[string]string{
		"username": viper.GetString(VIPER_PARAM_USERNAME),
		"password": viper.GetString(VIPER_PARAM_PASSWORD),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal login request: %w", err)
	}

	// Create HTTP request
	loginURL := viper.GetString(VIPER_PARAM_SERVER) + "/login"

	responseBody, responseStatusCode, serverTime, err := sendRequestWithServerTime(loginURL, METHOD_ENDPOINT_LOGIN, jsonData...)
	if err != nil {
		return "", time.Time{}, err
	}

	// Check HTTP status
	if responseStatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("login failed with status %d: %s", responseStatusCode, string(responseBody))
	}

	// Parse response
	var loginResp map[string]string
	if err := json.Unmarshal(responseBody, &loginResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse login response: %w", err)
	}

	token, ok := loginResp["token"]
	if !ok || token == "" {
		return "", time.Time{}, fmt.Errorf("no token in response")
	}

	return token, serverTime, nil
}

// saveAuthToken saves the authentication token and auth settings to the config file
func saveAuthToken() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, CONFIG_DIR)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, CONFIG_FILE)

	// Convert caCertPath to absolute path if provided
	if viper.GetString(VIPER_PARAM_CACERT) != "" {
		absCertPath, err := filepath.Abs(viper.GetString(VIPER_PARAM_CACERT))
		if err != nil {
			return fmt.Errorf("failed to convert CA cert path to absolute: %w", err)
		}
		viper.Set(VIPER_PARAM_CACERT, absCertPath)
	}

	save := viper.New()
	save.Set("api.server", viper.GetString(VIPER_PARAM_SERVER))
	save.Set("api.token", viper.GetString(VIPER_PARAM_AUTHPF_TOKEN))
	save.Set("api.cacert", viper.GetString(VIPER_PARAM_CACERT))
	save.Set("api.insecure", viper.GetBool(VIPER_PARAM_INSECURE))

	if err := save.WriteConfigAs(configFile); err != nil {
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

	configDir := filepath.Join(home, CONFIG_DIR)
	configFile := filepath.Join(configDir, CONFIG_FILE)

	if err := viper.New().WriteConfigAs(configFile); err != nil {
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

	configDir := filepath.Join(home, CONFIG_DIR)
	credentialsFile := filepath.Join(configDir, CREDENTIALS_FILE)

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

	configDir := filepath.Join(home, CONFIG_DIR)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	credentialsFile := filepath.Join(configDir, CREDENTIALS_FILE)

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

// tokenValidation is the server's verdict on the stored token.
type tokenValidation struct {
	valid bool
	// expiresAt is the JWT exp claim, zero when the token carries none or cannot be parsed.
	expiresAt time.Time
	// serverTime is the server clock from the response Date header, zero when it sent none.
	serverTime time.Time
}

// remaining is the token lifetime left on the server clock.
func (v tokenValidation) remaining() time.Duration {
	if v.expiresAt.IsZero() {
		return 0
	}
	if v.serverTime.IsZero() {
		// shortcut: server sent no clock at all, our own clock is the last option
		return time.Until(v.expiresAt)
	}
	return v.expiresAt.Sub(v.serverTime)
}

// printValid reports the token as valid, which the caller must only do after the server
// accepted it. A client clock that disagrees with the server is reported as a warning and
// never changes the verdict.
func (v tokenValidation) printValid() {
	fmt.Println("Token Validation: ✅ Valid")
	fmt.Fprint(os.Stderr, clockSkewWarning(v.serverTime))

	if v.expiresAt.IsZero() {
		return
	}

	fmt.Printf("  Expires at: %s\n", v.expiresAt.Format("2006-01-02 15:04:05 MST"))

	switch remaining := v.remaining(); {
	case remaining > 0:
		fmt.Printf("  Expires in: %s\n", formatDuration(remaining))
	case !v.serverTime.IsZero():
		fmt.Println("  Note: the server clock is past the token expiry, but the server accepted the token")
	}
}

// maxClockSkew is the client/server clock difference we accept silently. Below it a host
// without NTP still looks normal, above it something on that host is worth a look.
const maxClockSkew = 2 * time.Minute

// clockSkewWarning names the direction and size of a client/server clock difference, and
// returns "" when both clocks agree well enough or the server did not reveal its clock.
func clockSkewWarning(serverTime time.Time) string {
	if serverTime.IsZero() {
		return ""
	}

	clientTime := time.Now().UTC()
	skew := clientTime.Sub(serverTime)
	if skew < 0 {
		if -skew <= maxClockSkew {
			return ""
		}
		return fmt.Sprintf("⚠️  Time difference: client clock is %s BEHIND server clock (client %s, server %s), check NTP\n",
			formatDuration(-skew), clientTime.Format(time.RFC3339), serverTime.Format(time.RFC3339))
	}
	if skew <= maxClockSkew {
		return ""
	}

	return fmt.Sprintf("⚠️  Time difference: client clock is %s AHEAD of server clock (client %s, server %s), check NTP\n",
		formatDuration(skew), clientTime.Format(time.RFC3339), serverTime.Format(time.RFC3339))
}

// validateTokenAgainstServer asks the server whether the stored token is accepted. That
// answer is the only authority on validity: the client clock may be wrong and must never
// turn an accepted token into an expired one.
func validateTokenAgainstServer() (tokenValidation, error) {
	result := tokenValidation{}

	// An unparseable token is still the server's call, so a parse failure only leaves
	// expiresAt empty instead of failing the validation.
	if expiresAt, err := extractTokenExpiration(viper.GetString(VIPER_PARAM_AUTHPF_TOKEN)); err == nil {
		result.expiresAt = expiresAt
	}

	validateURL := viper.GetString(VIPER_PARAM_SERVER) + ENDPOINT_LOGIN

	responseBody, responseStatusCode, serverTime, err := sendRequestWithServerTime(validateURL, METHOD_ENDPOINT_AUTHPF_VIEW)
	if err != nil {
		return result, err
	}

	result.serverTime = serverTime

	// Check HTTP status
	switch responseStatusCode {
	case http.StatusOK:
		result.valid = true
		return result, nil
	case http.StatusUnauthorized:
		return result, nil
	}

	return result, fmt.Errorf("server returned status %d: %s", responseStatusCode, string(responseBody))
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
