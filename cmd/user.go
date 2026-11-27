package cmd

import (
	"fmt"

	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/spf13/cobra"
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
		cfg, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Check if user already exists
		if _, exists := cfg.Rbac.Users[username]; exists {
			return fmt.Errorf("user %s already exists", username)
		}

		hashedPasswordBytes, err := createPwHash(password)
		if err != nil {
			return err
		}
		hashedPassword := string(hashedPasswordBytes)

		// Create user
		if cfg.Rbac.Users == nil {
			cfg.Rbac.Users = make(map[string]config.ConfigFileRbacUsers)

		}

		newUser := config.ConfigFileRbacUsers{
			Password: hashedPassword,
			Role:     role,
		}

		if userID > 0 {
			newUser.UserID = userID
		}

		cfg.Rbac.Users[username] = newUser

		if err := validateForServer(cfg); err != nil {
			// The rule text already names the field, a usage block would only bury it.
			cmd.SilenceUsage = true
			return errServerReject(err)
		}

		// Save config
		if err := saveConfig(configPath, cfg); err != nil {
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

		if err := validateForServer(config); err != nil {
			cmd.SilenceUsage = true
			return errServerReject(err)
		}

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

		if err := validateForServer(config); err != nil {
			cmd.SilenceUsage = true
			return errServerReject(err)
		}

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
