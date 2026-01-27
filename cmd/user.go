package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users [server only]",
	Long:  "Create, modify, or delete users",
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long:  "Create a new user with username and password",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		userID, _ := cmd.Flags().GetInt("user-id")
		configPath, _ := cmd.Flags().GetString("config-path")

		if username == "" || password == "" {
			return fmt.Errorf("username and password are required")
		}

		if configPath == "" {
			configPath = "/usr/local/etc/authpf-api.conf"
		}

		// Load config
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Check if user already exists
		if _, exists := config.Rbac.Users[username]; exists {
			return fmt.Errorf("user %s already exists", username)
		}

		hashedPasswordBytes, err := createPwHash(password)
		if err != nil {
			return err
		}
		hashedPassword := string(hashedPasswordBytes)

		// Create user
		if config.Rbac.Users == nil {
			config.Rbac.Users = make(map[string]ConfigFileRbacUsers)
		}

		newUser := ConfigFileRbacUsers{
			Password: hashedPassword,
			Role:     role,
		}

		if userID > 0 {
			newUser.UserID = userID
		}

		config.Rbac.Users[username] = newUser

		// Save config
		if err := saveConfig(configPath, config); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		// Output
		fmt.Printf("User created successfully:\n")
		fmt.Printf("  Username: %s\n", username)
		fmt.Printf("  Password Hash: %s\n", hashedPassword)
		fmt.Printf("  Role: %s\n", role)
		if userID > 0 {
			fmt.Printf("  User ID: %d\n", userID)
		}

		return nil
	},
}

var userModifyCmd = &cobra.Command{
	Use:   "modify",
	Short: "Modify an existing user",
	Long:  "Modify username, password, role, or user ID of an existing user",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		userID, _ := cmd.Flags().GetInt("user-id")
		configPath, _ := cmd.Flags().GetString("config-path")

		if username == "" {
			return fmt.Errorf("username is required")
		}

		if configPath == "" {
			configPath = "/usr/local/etc/authpf-api.conf"
		}

		// Load config
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Check if user exists
		user, exists := config.Rbac.Users[username]
		if !exists {
			return fmt.Errorf("user %s not found", username)
		}

		// Update password if provided
		if password != "" {
			hashedPasswordBytes, err := createPwHash(password)
			if err != nil {
				return err
			}
			user.Password = string(hashedPasswordBytes)
		}

		// Update role if provided
		if role != "" {
			user.Role = role
		}

		// Update user ID if provided
		if userID > 0 {
			user.UserID = userID
		}

		config.Rbac.Users[username] = user

		// Save config
		if err := saveConfig(configPath, config); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		// Output
		fmt.Printf("User modified successfully:\n")
		fmt.Printf("  Username: %s\n", username)
		if password != "" {
			fmt.Printf("  Password Hash: %s\n", user.Password)
		}
		if role != "" {
			fmt.Printf("  Role: %s\n", role)
		}
		if userID > 0 {
			fmt.Printf("  User ID: %d\n", userID)
		}

		return nil
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	Long:  "Delete an existing user",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		configPath, _ := cmd.Flags().GetString("config-path")

		if username == "" {
			return fmt.Errorf("username is required")
		}

		if configPath == "" {
			configPath = "/usr/local/etc/authpf-api.conf"
		}

		// Load config
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Check if user exists
		if _, exists := config.Rbac.Users[username]; !exists {
			return fmt.Errorf("user %s not found", username)
		}

		// Delete user
		delete(config.Rbac.Users, username)

		// Save config
		if err := saveConfig(configPath, config); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("User deleted successfully: %s\n", username)
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Long:  "List all users configured in the system",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config-path")

		if configPath == "" {
			configPath = "/usr/local/etc/authpf-api.conf"
		}

		// Load config
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if len(config.Rbac.Users) == 0 {
			fmt.Println("No users configured")
			return nil
		}

		fmt.Println("Users:")
		for username, user := range config.Rbac.Users {
			fmt.Printf("  %s:\n", username)
			fmt.Printf("    Role: %s\n", user.Role)
			if user.UserID > 0 {
				fmt.Printf("    User ID: %d\n", user.UserID)
			}
			fmt.Printf("    Password Hash: %s\n", user.Password)
		}

		return nil
	},
}

func init() {
	// Create command
	userCreateCmd.Flags().StringP("username", "u", "", "Username")
	userCreateCmd.Flags().StringP("password", "p", "", "Password (will be hashed)")
	userCreateCmd.Flags().StringP("role", "r", "user", "User role")
	userCreateCmd.Flags().IntP("user-id", "i", 0, "User ID (optional)")
	userCreateCmd.Flags().StringP("config-path", "c", "", "Path to config file")

	// Modify command
	userModifyCmd.Flags().StringP("username", "u", "", "Username")
	userModifyCmd.Flags().StringP("password", "p", "", "New password (optional)")
	userModifyCmd.Flags().StringP("role", "r", "", "New role (optional)")
	userModifyCmd.Flags().IntP("user-id", "i", 0, "New user ID (optional)")
	userModifyCmd.Flags().StringP("config-path", "c", "", "Path to config file")

	// Delete command
	userDeleteCmd.Flags().StringP("username", "u", "", "Username")
	userDeleteCmd.Flags().StringP("config-path", "c", "", "Path to config file")

	// List command
	userListCmd.Flags().StringP("config-path", "c", "", "Path to config file")

	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userModifyCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userListCmd)
}

// Helper functions
func loadConfig(configPath string) (*ConfigFile, error) {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := &ConfigFile{}
	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func saveConfig(configPath string, config *ConfigFile) error {
	// Read the entire file to preserve other sections
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	// Unmarshal into a generic map to preserve all sections
	var fullConfig map[string]interface{}
	err = yaml.Unmarshal(yamlFile, &fullConfig)
	if err != nil {
		return err
	}

	// Update only the rbac section
	rbacData := make(map[string]interface{})
	rbacData["roles"] = config.Rbac.Roles

	// Convert users to the proper format
	usersData := make(map[string]interface{})
	for username, user := range config.Rbac.Users {
		userData := make(map[string]interface{})
		userData["password"] = user.Password
		userData["role"] = user.Role
		if user.UserID > 0 {
			userData["userId"] = user.UserID
		}
		usersData[username] = userData
	}
	rbacData["users"] = usersData

	fullConfig["rbac"] = rbacData

	// Marshal back to YAML
	yamlData, err := yaml.Marshal(fullConfig)
	if err != nil {
		return err
	}

	// Write to file
	err = os.WriteFile(configPath, yamlData, 0640)
	if err != nil {
		return err
	}

	return nil
}
