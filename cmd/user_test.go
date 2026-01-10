package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestLoadConfig tests the loadConfig function
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(*ConfigFile) bool
	}{
		{
			name: "valid config",
			content: `rbac:
  roles:
    admin:
      permissions:
        - read
        - write
  users:
    testuser:
      password: abc123
      role: admin
      userId: 1`,
			wantError: false,
			validate: func(cf *ConfigFile) bool {
				return cf.Rbac.Users["testuser"].Password == "abc123" &&
					cf.Rbac.Users["testuser"].Role == "admin" &&
					cf.Rbac.Users["testuser"].UserID == 1
			},
		},
		{
			name: "empty config",
			content: `rbac:
  roles: {}
  users: {}`,
			wantError: false,
			validate: func(cf *ConfigFile) bool {
				return len(cf.Rbac.Users) == 0
			},
		},
		{
			name:      "invalid yaml",
			content:   "invalid: yaml: content:",
			wantError: true, // YAML parser throws error on invalid syntax
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write test content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			tmpFile.Close()

			// Test loadConfig
			config, err := loadConfig(tmpFile.Name())
			if (err != nil) != tt.wantError {
				t.Errorf("loadConfig() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if err == nil && tt.validate != nil {
				if !tt.validate(config) {
					t.Errorf("loadConfig() validation failed")
				}
			}
		})
	}
}

// TestLoadConfigFileNotFound tests loadConfig with non-existent file
func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := loadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Errorf("loadConfig() expected error for non-existent file")
	}
}

// TestSaveConfig tests the saveConfig function
func TestSaveConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *ConfigFile
		wantError bool
		validate  func(string) bool
	}{
		{
			name: "save simple config",
			config: &ConfigFile{
				Rbac: ConfigFileRbac{
					Roles: map[string]ConfigFileRbacRoles{
						"admin": {
							Permissions: []string{"read", "write"},
						},
					},
					Users: map[string]ConfigFileRbacUsers{
						"testuser": {
							Password: "hashedpassword",
							Role:     "admin",
							UserID:   1,
						},
					},
				},
			},
			wantError: false,
			validate: func(path string) bool {
				data, err := os.ReadFile(path)
				if err != nil {
					return false
				}

				var config ConfigFile
				err = yaml.Unmarshal(data, &config)
				if err != nil {
					return false
				}

				return config.Rbac.Users["testuser"].Password == "hashedpassword" &&
					config.Rbac.Users["testuser"].Role == "admin" &&
					config.Rbac.Users["testuser"].UserID == 1
			},
		},
		{
			name: "save config without user id",
			config: &ConfigFile{
				Rbac: ConfigFileRbac{
					Roles: map[string]ConfigFileRbacRoles{},
					Users: map[string]ConfigFileRbacUsers{
						"user2": {
							Password: "hash2",
							Role:     "user",
						},
					},
				},
			},
			wantError: false,
			validate: func(path string) bool {
				data, err := os.ReadFile(path)
				if err != nil {
					return false
				}

				var fullConfig map[string]interface{}
				err = yaml.Unmarshal(data, &fullConfig)
				if err != nil {
					return false
				}

				rbac, ok := fullConfig["rbac"].(map[string]interface{})
				if !ok {
					return false
				}

				users, ok := rbac["users"].(map[string]interface{})
				if !ok {
					return false
				}

				user2, ok := users["user2"].(map[string]interface{})
				if !ok {
					return false
				}

				// Check that userId is not present when it's 0
				_, hasUserID := user2["userId"]
				return !hasUserID && user2["password"] == "hash2"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with initial content
			tmpFile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write initial YAML structure
			initialContent := `rbac:
  roles: {}
  users: {}`
			if _, err := tmpFile.WriteString(initialContent); err != nil {
				t.Fatalf("failed to write initial content: %v", err)
			}
			tmpFile.Close()

			// Test saveConfig
			err = saveConfig(tmpFile.Name(), tt.config)
			if (err != nil) != tt.wantError {
				t.Errorf("saveConfig() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if err == nil && tt.validate != nil {
				if !tt.validate(tmpFile.Name()) {
					t.Errorf("saveConfig() validation failed")
				}
			}
		})
	}
}

// TestHashPassword tests password hashing consistency
func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hash1 := sha256.Sum256([]byte(password))
	hashedPassword1 := hex.EncodeToString(hash1[:])

	hash2 := sha256.Sum256([]byte(password))
	hashedPassword2 := hex.EncodeToString(hash2[:])

	if hashedPassword1 != hashedPassword2 {
		t.Errorf("password hashing is not consistent")
	}

	// Verify hash format
	if len(hashedPassword1) != 64 {
		t.Errorf("SHA256 hash should be 64 characters, got %d", len(hashedPassword1))
	}
}

// TestConfigFileStructures tests the config file data structures
func TestConfigFileStructures(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{
			name: "ConfigFileRbacUsers structure",
			testFunc: func(t *testing.T) {
				user := ConfigFileRbacUsers{
					Password: "hash",
					Role:     "admin",
					UserID:   42,
				}
				if user.Password != "hash" || user.Role != "admin" || user.UserID != 42 {
					t.Errorf("ConfigFileRbacUsers structure not working correctly")
				}
			},
		},
		{
			name: "ConfigFileRbacRoles structure",
			testFunc: func(t *testing.T) {
				role := ConfigFileRbacRoles{
					Permissions: []string{"read", "write", "delete"},
				}
				if len(role.Permissions) != 3 {
					t.Errorf("ConfigFileRbacRoles structure not working correctly")
				}
			},
		},
		{
			name: "ConfigFile structure",
			testFunc: func(t *testing.T) {
				config := &ConfigFile{
					Rbac: ConfigFileRbac{
						Roles: make(map[string]ConfigFileRbacRoles),
						Users: make(map[string]ConfigFileRbacUsers),
					},
				}
				if config.Rbac.Roles == nil || config.Rbac.Users == nil {
					t.Errorf("ConfigFile structure not initialized correctly")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.testFunc)
	}
}

// TestLoadAndSaveRoundTrip tests loading and saving config preserves data
func TestLoadAndSaveRoundTrip(t *testing.T) {
	// Create temporary file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write initial config
	initialContent := `rbac:
  roles:
    admin:
      permissions:
        - read
        - write
    user:
      permissions:
        - read
  users:
    alice:
      password: alicehash
      role: admin
      userId: 1
    bob:
      password: bobhash
      role: user`

	if _, err := tmpFile.WriteString(initialContent); err != nil {
		t.Fatalf("failed to write initial content: %v", err)
	}
	tmpFile.Close()

	// Load config
	config, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadConfig() failed: %v", err)
	}

	// Modify config
	config.Rbac.Users["charlie"] = ConfigFileRbacUsers{
		Password: "charliehash",
		Role:     "user",
		UserID:   3,
	}

	// Save config
	err = saveConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("saveConfig() failed: %v", err)
	}

	// Load again and verify
	config2, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("second loadConfig() failed: %v", err)
	}

	// Verify all users are present
	if len(config2.Rbac.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(config2.Rbac.Users))
	}

	if config2.Rbac.Users["alice"].Password != "alicehash" {
		t.Errorf("alice's password was not preserved")
	}

	if config2.Rbac.Users["charlie"].UserID != 3 {
		t.Errorf("charlie's user ID was not preserved")
	}
}

// TestEmptyUsersMap tests handling of empty users map
func TestEmptyUsersMap(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write config with empty users
	content := `rbac:
  roles: {}
  users: {}`

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	tmpFile.Close()

	config, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadConfig() failed: %v", err)
	}

	// Add user to empty map
	if config.Rbac.Users == nil {
		config.Rbac.Users = make(map[string]ConfigFileRbacUsers)
	}

	config.Rbac.Users["newuser"] = ConfigFileRbacUsers{
		Password: "newhash",
		Role:     "user",
	}

	err = saveConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("saveConfig() failed: %v", err)
	}

	// Verify
	config2, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("second loadConfig() failed: %v", err)
	}

	if len(config2.Rbac.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(config2.Rbac.Users))
	}
}

// TestYAMLUnmarshalWithOmitEmpty tests YAML unmarshaling with omitempty
func TestYAMLUnmarshalWithOmitEmpty(t *testing.T) {
	yamlContent := `rbac:
  roles: {}
  users:
    user1:
      password: hash1
      role: admin
    user2:
      password: hash2
      role: user
      userId: 5`

	var config ConfigFile
	err := yaml.Unmarshal([]byte(yamlContent), &config)
	if err != nil {
		t.Fatalf("yaml.Unmarshal() failed: %v", err)
	}

	// user1 should have UserID = 0 (default)
	if config.Rbac.Users["user1"].UserID != 0 {
		t.Errorf("user1 UserID should be 0, got %d", config.Rbac.Users["user1"].UserID)
	}

	// user2 should have UserID = 5
	if config.Rbac.Users["user2"].UserID != 5 {
		t.Errorf("user2 UserID should be 5, got %d", config.Rbac.Users["user2"].UserID)
	}
}

// TestMultipleUsersHandling tests handling multiple users
func TestMultipleUsersHandling(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `rbac:
  roles: {}
  users: {}`

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	tmpFile.Close()

	config, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadConfig() failed: %v", err)
	}

	// Add multiple users
	if config.Rbac.Users == nil {
		config.Rbac.Users = make(map[string]ConfigFileRbacUsers)
	}

	users := []struct {
		username string
		password string
		role     string
		userID   int
	}{
		{"user1", "hash1", "admin", 1},
		{"user2", "hash2", "user", 2},
		{"user3", "hash3", "user", 0},
		{"user4", "hash4", "admin", 4},
	}

	for _, u := range users {
		config.Rbac.Users[u.username] = ConfigFileRbacUsers{
			Password: u.password,
			Role:     u.role,
			UserID:   u.userID,
		}
	}

	err = saveConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("saveConfig() failed: %v", err)
	}

	// Load and verify
	config2, err := loadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("second loadConfig() failed: %v", err)
	}

	if len(config2.Rbac.Users) != 4 {
		t.Errorf("expected 4 users, got %d", len(config2.Rbac.Users))
	}

	for _, u := range users {
		user, exists := config2.Rbac.Users[u.username]
		if !exists {
			t.Errorf("user %s not found", u.username)
			continue
		}

		if user.Password != u.password {
			t.Errorf("user %s password mismatch", u.username)
		}

		if user.Role != u.role {
			t.Errorf("user %s role mismatch", u.username)
		}

		if user.UserID != u.userID {
			t.Errorf("user %s userID mismatch: expected %d, got %d", u.username, u.userID, user.UserID)
		}
	}
}

// TestConfigPathHandling tests different config path scenarios
func TestConfigPathHandling(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "authpf-api.conf")

	// Create initial config file
	content := `rbac:
  roles: {}
  users: {}`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Test loading from custom path
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig() with custom path failed: %v", err)
	}

	if config == nil {
		t.Errorf("loadConfig() returned nil config")
	}

	// Test saving to custom path
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "testhash",
			Role:     "admin",
		},
	}

	err = saveConfig(configPath, config)
	if err != nil {
		t.Fatalf("saveConfig() with custom path failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("config file not found after save: %v", err)
	}
}
