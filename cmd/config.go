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

// yamlMapping hands a parsed YAML mapping back as a string-keyed map, or nil when the value is no
// mapping at all.
//
// yaml.v3 decodes a mapping into map[string]interface{} only while every one of its keys is a
// string. A single numeric- or bool-shaped key - a user named 1001, which the server's own
// username pattern allows, or a "2024: audited" note someone left under rbac: - turns the whole
// map into a map[interface{}]interface{}. Asserting on the string shape alone would then read
// such a subtree as missing and write it fresh from the struct, which is exactly the loss
// saveConfig exists to prevent. Re-keying costs nothing: the server's typed decode reads those
// keys as strings as well, and yaml writes them back quoted.
func yamlMapping(value interface{}) map[string]interface{} {
	switch mapping := value.(type) {
	case map[string]interface{}:
		return mapping
	case map[interface{}]interface{}:
		converted := make(map[string]interface{}, len(mapping))
		for key, entry := range mapping {
			converted[fmt.Sprintf("%v", key)] = entry
		}
		return converted
	default:
		return nil
	}
}

// saveConfig writes the rbac section back to configPath. Every other section of the file keeps
// its content, though not its formatting; see the last paragraph.
//
// The section is rebuilt on top of the file's own parsed rbac subtree rather than out of the
// struct the commands are driven by. ConfigFileRbacUsers does carry userIp, macros and pfTable,
// but the loop that rebuilt the section named only password, role and userId, so the other three
// were dropped from every user in the file on every write - the pinned source address of an
// anchor, the macro definitions a user's rules file is loaded with, and the pf table the address
// is added to, all settings the server hands straight to pfctl - and every key the struct does
// not model at all went with them, under rbac: or under a role. A routine password change
// therefore rewrote the whole file's access-control posture and exited 0, and the server still
// accepted the result: it validates shape, not preservation.
//
// So the parsed file is the base and only the keys these commands actually edit are overlaid on
// it. If a command ever starts editing userIp, macros or pfTable, it has to write them here too.
//
// What is still not preserved is how the file was written: the result is re-marshalled from
// decoded values, so comments, anchors and key order normalise on every save.
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
	if fullConfig == nil {
		// An empty file holds no sections to overlay onto. Writing rbac alone into it would
		// hand the server a file it refuses to start from, and reaching this line at all means
		// a caller skipped the validation these commands run first.
		return fmt.Errorf("%s contains no configuration to update", configPath)
	}

	// Update only the rbac section, and update it on top of what the file already says.
	rbacData := yamlMapping(fullConfig["rbac"])
	if rbacData == nil {
		// No rbac section, or one that is not a mapping. Either is written fresh; loadConfig
		// would already have refused a scalar rbac section, so this is defence in depth.
		rbacData = make(map[string]interface{})
	}

	// Roles are written only when the loaded config carries them, so a file that declares no
	// roles here is not edited into declaring an empty role store, which the server rejects
	// for every user in the file.
	if config.Rbac.Roles != nil {
		rolesRaw := yamlMapping(rbacData["roles"])
		rolesData := make(map[string]interface{}, len(config.Rbac.Roles))
		for roleName, role := range config.Rbac.Roles {
			roleData := yamlMapping(rolesRaw[roleName])
			if roleData == nil {
				roleData = make(map[string]interface{})
			}
			roleData["permissions"] = role.Permissions
			rolesData[roleName] = roleData
		}
		rbacData["roles"] = rolesData
	}

	// Convert users to the proper format, again on top of their own stored entries. userId is
	// the one key that is removed rather than left alone: 0 means unset here, and an account
	// must not keep an id this tool has decided it does not have.
	usersRaw := yamlMapping(rbacData["users"])
	usersData := make(map[string]interface{}, len(config.Rbac.Users))
	for username, user := range config.Rbac.Users {
		userData := yamlMapping(usersRaw[username])
		if userData == nil {
			// A new account, or a stored entry that is not a mapping.
			userData = make(map[string]interface{})
		}
		userData["password"] = user.Password
		userData["role"] = user.Role
		if user.UserID > 0 {
			userData["userId"] = user.UserID
		} else {
			delete(userData, "userId")
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
