package cmd

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"

	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration [server only]",
	Long:  "Check and validate configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show configuration",
	Long:  "Display the current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config-path")

		// Server mode: show local config
		if configPath == "" {
			configPath = "/usr/local/etc/authpf-api.conf"
		}

		// Load and parse the config file
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		fmt.Printf("Configuration from: %s\n\n", configPath)

		fmt.Printf("=== Defaults ===\n")

		fmt.Printf("Filepath pfctl: \t%s\n", config.Defaults.PfctlBinary)

		fmt.Printf("\n=== AuthPF ===\n")

		fmt.Printf("Anchor Timeout: \t\t%s\n", config.AuthPF.Timeout)
		fmt.Printf("Root Folder: \t\t%s\n", config.AuthPF.UserRulesRootFolder)
		fmt.Printf("Rules Filename: \t\t%s\n", config.AuthPF.UserRulesFile)
		fmt.Printf("Anchor Base: \t\t%s\n", config.AuthPF.AnchorName)

		if len(config.AuthPF.FlushFilter) > 0 {
			fmt.Printf("PF Flush Filter: \n")
			for _, filter := range config.AuthPF.FlushFilter {
				fmt.Printf("  - %s\n", filter)
			}
		} else {
			fmt.Println("PF Flush Filter: not Set")
		}

		// Display the parsed configuration
		fmt.Printf("\n=== RBAC ===\n")
		if len(config.Rbac.Roles) > 0 {
			for roleName, role := range config.Rbac.Roles {
				fmt.Printf("%s:\n", roleName)
				if len(role.Permissions) > 0 {
					for _, perm := range role.Permissions {
						fmt.Printf("  - %s\n", perm)
					}
				} else {
					fmt.Println("(none)")
				}
			}
		} else {
			fmt.Println("\nRoles: (none configured)")
		}
		fmt.Println("\n=== Users ===")

		if len(config.Rbac.Users) > 0 {
			for username, user := range config.Rbac.Users {
				fmt.Printf("\n%s:\n", username)
				fmt.Printf("  Role: \t%s\n", user.Role)
				fmt.Printf("  User ID: \t%d\n", user.UserID)
				if len(user.Password) > 0 {
					fmt.Printf("  Password: \tis Set\n")
				}
			}
		} else {
			fmt.Println("\nUsers: (none configured)")
		}

		return nil
	},
}

// loadConfig reads the server configuration file at configPath.
func loadConfig(configPath string) (*config.ConfigFile, error) {
	if err := checkConfigTarget(configPath); err != nil {
		return nil, err
	}

	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := &config.ConfigFile{}
	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// saveConfig writes the rbac section back to configPath and leaves every other section of the
// file exactly as it was.
func saveConfig(configPath string, config *config.ConfigFile) error {
	// Read the entire file to preserve other sections
	if err := checkConfigTarget(configPath); err != nil {
		return err
	}

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

// checkConfigTarget refuses a --config-path that is not the plain file it claims to be.
// os.ReadFile and os.WriteFile both follow symlinks, so without this check a single -c
// argument turns the server-mode commands into a read, or an in-place rewrite, of whatever
// file a planted link points at. Operators legitimately point -c at any path, so what is
// constrained here is the kind of file, never where it sits.
func checkConfigTarget(configPath string) error {
	info, err := os.Lstat(configPath)
	if err != nil {
		return err
	}

	return checkPlainFile(configPath, info)
}

// checkPlainFile reports what makes an already lstat'ed config path unusable: a symlink, or
// anything that is not a regular file. A FIFO in that position used to block the command
// until some writer showed up.
func checkPlainFile(configPath string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config path %s is a symlink, refusing to follow it", configPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config path %s is not a regular file, refusing to use it", configPath)
	}

	return nil
}

// The write gate: the server refuses to start on an rbac.users section it does not accept, and it
// does that check at its own startup, in another process: by then the CLI has already returned 0
// and the last known good file is gone. So the rules below run on the fully mutated configuration
// before a write, which is the only moment where the damage can still be prevented.
//
// These are the four rules authpf-api enforces on rbac.users that a user command can actually
// break. They are deliberately a copy and not pkg/config.Validate(): that method also stats
// defaults.pfctlBinary, looks elevatorMode up in PATH, checks that authpf.userRulesRootFolder
// exists and reads the TLS key, so a CLI run from a host without a pfctl - or without
// permission on the key - would refuse writes that are perfectly fine. Validate() is about the
// whole machine; a write here only ever changes rbac.users.
//
// What is therefore checked is every user in the resulting file, not only the one being
// written: a userId only collides in combination, and "no users left" is a property of the
// result. A file that is already broken elsewhere in rbac.users blocks writes until it is
// repaired, and deleting the offending user is itself a valid write, so the repair path
// stays open.
//
// What is deliberately not checked: the password field. The CLI always writes a fresh bcrypt
// hash, while a file an operator edited by hand may hold anything there, and refusing every
// further change to such a file over a value this command never touched is a worse outcome
// than the server's own startup error.

// serverUsernameRegex and serverMaxUsernameLength mirror the server's rbacUsernameRegex and its
// 255 character cap. Keep them in step with pkg/config when the dependency moves.
var serverUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const serverMaxUsernameLength = 255

// validateForServer reports whether the server would accept the rbac.users section of cfg, in
// the wording the server itself uses. An error means the write must not happen.
func validateForServer(cfg *config.ConfigFile) error {
	if len(cfg.Rbac.Users) == 0 {
		return fmt.Errorf("rbac.users: no users configured")
	}

	// Sorted, so the same file always names the same user in its error.
	for _, username := range slices.Sorted(maps.Keys(cfg.Rbac.Users)) {
		user := cfg.Rbac.Users[username]

		if len(username) > serverMaxUsernameLength || !serverUsernameRegex.MatchString(username) {
			return fmt.Errorf(
				"rbac.users: invalid username %q: must match [a-zA-Z0-9_-]+ and be at most %d characters",
				username, serverMaxUsernameLength,
			)
		}

		if user.Role == "" {
			return fmt.Errorf("rbac.users.%s.role: must not be empty", username)
		}

		if _, known := cfg.Rbac.Roles[user.Role]; !known {
			return fmt.Errorf("rbac.users.%s.role: unknown role %q", username, user.Role)
		}
	}

	return validateUserIDs(cfg)
}

// validateUserIDs rejects a negative userId and one that two users share. A userId of 0
// means "not set" and is what saveConfig leaves out of the file.
func validateUserIDs(cfg *config.ConfigFile) error {
	seen := map[int]string{}

	for _, username := range slices.Sorted(maps.Keys(cfg.Rbac.Users)) {
		userID := cfg.Rbac.Users[username].UserID

		if userID < 0 {
			return fmt.Errorf("rbac.users.%s.userId: must not be negative", username)
		}

		if userID == 0 {
			continue
		}

		if previous, taken := seen[userID]; taken {
			return fmt.Errorf(
				"rbac.users.%s.userId: duplicate userId %d also configured for user %q",
				username, userID, previous,
			)
		}
		seen[userID] = username
	}

	return nil
}

// errServerReject frames a rule violation as what it is: the file this command is about to
// write is one the server would not start from.
func errServerReject(err error) error {
	return fmt.Errorf("refusing to write configuration the server would reject: %w", err)
}

func init() {
	// Show command
	configShowCmd.Flags().StringP("config-path", "c", "", "Path to config file")

	// configCmd.AddCommand(configCheckCmd)
	// configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configShowCmd)
}
