package cmd

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Everything a --config-path can be and become lives here: which file the tool may read and
// write, what a saved file must keep, and which rbac.users contents the authpf-api server would
// refuse to start from.

// The server-mode commands take their destination from -c/--config-path, and both the read
// and the write follow a link at that path. What these cases hold the code to is the decision
// to use only a regular file there; the location itself stays free, because pointing -c at any
// path is what the flag is for.

const plainConfig = `rbac:
  roles: {}
  users: {}
`

func writePlainConfig(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(plainConfig), 0600); err != nil {
		t.Fatal(err)
	}
	// The mode is set apart from the write so a permissive umask cannot undo what is under test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// withUser returns the config of path with one more user in it, the way user create does.
func withUser(t *testing.T, path, username string) *config.ConfigFile {
	t.Helper()

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%s) = %v", path, err)
	}
	cfg.Rbac.Users[username] = config.ConfigFileRbacUsers{Password: "hash", Role: "admin"}

	return cfg
}

func fileContents(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestLoadConfigRefusesAConfigPathThatIsALink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	writePlainConfig(t, victim, 0o600)

	link := filepath.Join(dir, "planted-link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(link); err == nil {
		t.Fatal("loadConfig() read through a symlink, want it refused")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("loadConfig() error = %v, want it to name the symlink", err)
	}
}

func TestLoadConfigRefusesAConfigPathThatIsNotAFile(t *testing.T) {
	// A FIFO in this position used to block the command until a writer turned up, and
	// /dev/null used to parse as an empty config with no users at all.
	if _, err := os.Lstat("/dev/null"); err != nil {
		t.Skip("no /dev/null on this platform")
	}

	if _, err := loadConfig("/dev/null"); err == nil {
		t.Fatal("loadConfig(\"/dev/null\") succeeded, want it refused as not a regular file")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("loadConfig() error = %v, want it to say not a regular file", err)
	}
}

func TestSaveConfigRefusesAConfigPathThatIsALink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	writePlainConfig(t, victim, 0o600)
	before := fileContents(t, victim)

	link := filepath.Join(dir, "planted-link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	if err := saveConfig(link, withUser(t, victim, "intruder")); err == nil {
		t.Fatal("saveConfig() wrote through a symlink, want it refused")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("saveConfig() error = %v, want it to name the symlink", err)
	}

	if got := fileContents(t, victim); got != before {
		t.Errorf("victim was rewritten through the link:\n%s", got)
	}
	assertNoStrayFiles(t, dir, "victim.conf", "planted-link")
}

// The save writes the file where it is, so nothing about it changes except its content. Both
// of these are properties the report measured on the unpatched code and that must survive here.
func TestSaveConfigKeepsModeAndContentsOfOtherSections(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authpf-api.conf")
			writePlainConfig(t, path, mode)

			if err := saveConfig(path, withUser(t, path, "operator")); err != nil {
				t.Fatalf("saveConfig() = %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != mode {
				t.Errorf("mode after save = %04o, want the original %04o", got, mode)
			}
		})
	}
}

// A read-only config fails closed on the open. That is the behaviour before and after this
// change; it is pinned here so a later switch to replacing the file does not quietly drop it.
func TestSaveConfigRefusesAReadOnlyConfigFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not stopped by the mode bits, before this change either")
	}

	path := filepath.Join(t.TempDir(), "authpf-api.conf")
	writePlainConfig(t, path, 0o444)
	before := fileContents(t, path)

	if err := saveConfig(path, withUser(t, path, "operator")); err == nil {
		t.Fatal("saveConfig() wrote to a read-only config, want it refused")
	}

	if got := fileContents(t, path); got != before {
		t.Errorf("read-only config was rewritten:\n%s", got)
	}
	assertNoStrayFiles(t, filepath.Dir(path), "authpf-api.conf")
}

// What a saved file must keep beyond its top-level sections. The save rebuilds rbac, and the
// struct it is driven from models password, role and userId of a user and nothing else.
// Everything the file says beyond that has to survive, because the server acts on it: userIp is
// the address handed to pfctl as -D user_ip= and the address added to the pf table, macros become
// -D arguments for that user's rules file, and pfTable picks the table the address is added to.
// Losing any of them is not cosmetic drift, it is a change of firewall policy for accounts no one
// named - and the server accepts the reduced file, so nothing reports it.
//
// The fixture below puts one account per interesting field, plus keys no version of the struct
// models at all.
const policyConfig = `rbac:
  lastReviewed: checked by hand in november
  roles:
    admin:
      permissions:
        - view
      description: read-only auditor
    user:
      permissions:
        - view
  users:
    authpf-admin:
      password: "$2a$12$abcdefghijklmnopqrstuv"
      role: admin
      userId: 1000
      pfTable: authpf_admins
    authpf-user1:
      password: "$2a$12$zyxwvutsrqponmlkjihg"
      role: user
      userId: 1001
      userIp: 192.168.0.10
      macros:
        server_1_addr: 10.127.2.1
        server_1_port: 22
      futureField: a key this tool has never heard of
`

// rbacSection reads the rbac section of a written file back as raw YAML, for the keys the typed
// struct cannot show.
func rbacSection(t *testing.T, path string) map[string]interface{} {
	t.Helper()

	var full map[string]interface{}
	if err := yaml.Unmarshal([]byte(fileContents(t, path)), &full); err != nil {
		t.Fatal(err)
	}

	rbac, ok := full["rbac"].(map[string]interface{})
	if !ok {
		t.Fatalf("no rbac mapping in the saved file:\n%s", fileContents(t, path))
	}

	return rbac
}

// rbacUserSection is one user's entry as the file holds it.
func rbacUserSection(t *testing.T, path, username string) map[string]interface{} {
	t.Helper()

	users, ok := rbacSection(t, path)["users"].(map[string]interface{})
	if !ok {
		t.Fatalf("no rbac.users mapping in the saved file:\n%s", fileContents(t, path))
	}

	user, ok := users[username].(map[string]interface{})
	if !ok {
		t.Fatalf("no rbac.users.%s mapping in the saved file:\n%s", username, fileContents(t, path))
	}

	return user
}

func TestSaveConfigKeepsThePolicyFieldsOfUntouchedUsers(t *testing.T) {
	path := writeTestConfig(t, policyConfig)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}

	// The one thing user create does: add an account.
	cfg.Rbac.Users["carol"] = config.ConfigFileRbacUsers{
		Password: "hash",
		Role:     "user",
		UserID:   3001,
	}

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig() = %v", err)
	}

	after, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the saved file no longer parses: %v", err)
	}

	admin := after.Rbac.Users["authpf-admin"]
	if admin.PfTable != "authpf_admins" {
		t.Errorf("pfTable of an untouched user = %q, want authpf_admins", admin.PfTable)
	}

	user1 := after.Rbac.Users["authpf-user1"]
	if user1.UserIP != "192.168.0.10" {
		t.Errorf("userIp of an untouched user = %q, want 192.168.0.10", user1.UserIP)
	}
	wantMacros := map[string]string{"server_1_addr": "10.127.2.1", "server_1_port": "22"}
	if !maps.Equal(user1.Macros, wantMacros) {
		t.Errorf("macros of an untouched user = %v, want %v", user1.Macros, wantMacros)
	}

	// The keys the save is about are still the ones it writes.
	carol := after.Rbac.Users["carol"]
	if carol.Password != "hash" || carol.Role != "user" || carol.UserID != 3001 {
		t.Errorf("the new user was not written as given: %+v", carol)
	}
	if got := after.Rbac.Users["authpf-admin"]; got.Password == "hash" || got.Role != "admin" || got.UserID != 1000 {
		t.Errorf("an untouched user's password, role or userId moved: %+v", got)
	}

	// And the keys no struct models are still there, at all three levels they can sit at.
	if got := rbacSection(t, path)["lastReviewed"]; got != "checked by hand in november" {
		t.Errorf("an unmodelled key under rbac = %v, want it kept", got)
	}
	if got := rbacUserSection(t, path, "authpf-user1")["futureField"]; got != "a key this tool has never heard of" {
		t.Errorf("an unmodelled key under a user = %v, want it kept", got)
	}
	roles, ok := rbacSection(t, path)["roles"].(map[string]interface{})
	if !ok {
		t.Fatal("the save dropped rbac.roles")
	}
	adminRole, ok := roles["admin"].(map[string]interface{})
	if !ok {
		t.Fatalf("rbac.roles.admin is no longer a mapping: %v", roles["admin"])
	}
	if got := adminRole["description"]; got != "read-only auditor" {
		t.Errorf("an unmodelled key under a role = %v, want it kept", got)
	}
	perms, ok := adminRole["permissions"].([]interface{})
	if !ok || len(perms) != 1 || perms[0] != "view" {
		t.Errorf("rbac.roles.admin.permissions = %v, want [view]", adminRole["permissions"])
	}
}

// A file whose roles are not declared in it must not be edited into declaring an empty role
// store. The server refuses every user whose role no role in the file defines, so an injected
// roles: {} is a server that no longer starts - over a change that only added one account.
func TestSaveConfigWritesNoRolesSectionIntoAFileThatHasNone(t *testing.T) {
	path := writeTestConfig(t, `rbac:
  users:
    authpf-admin:
      password: "$2a$12$abcdefghijklmnopqrstuv"
      role: admin
      userIp: 192.168.0.10
`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}
	cfg.Rbac.Users["carol"] = config.ConfigFileRbacUsers{Password: "hash", Role: "user"}

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig() = %v", err)
	}

	rbac := rbacSection(t, path)
	if roles, ok := rbac["roles"]; ok {
		t.Errorf("the save wrote a roles section into a file that declares none: %v", roles)
	}
	after, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the saved file no longer parses: %v", err)
	}
	if got := after.Rbac.Users["authpf-admin"].UserIP; got != "192.168.0.10" {
		t.Errorf("userIp of an untouched user = %q, want 192.168.0.10", got)
	}
}

// userId is the one modelled key a user can lose, so the save has to remove it rather than leave
// a stored one standing: 0 means unset, and an account must not keep an id this tool decided it
// does not have - two accounts sharing one id is what the write gate refuses to produce.
func TestSaveConfigRemovesAUserIDTheConfigLeavesUnset(t *testing.T) {
	path := writeTestConfig(t, policyConfig)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}
	user := cfg.Rbac.Users["authpf-user1"]
	user.UserID = 0
	cfg.Rbac.Users["authpf-user1"] = user

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig() = %v", err)
	}

	if _, ok := rbacUserSection(t, path, "authpf-user1")["userId"]; ok {
		t.Error("userId survived a config that leaves it unset")
	}
	if got := rbacUserSection(t, path, "authpf-user1")["userIp"]; got != "192.168.0.10" {
		t.Errorf("removing userId took userIp with it: %v", got)
	}
}

// A user the file names but describes as nothing at all (rbac.users.ghost: with no mapping under
// it) is the one entry shape the overlay cannot copy from. It has to come out as an entry rather
// than a panic, exactly as the old code wrote it, and it must not disturb the users beside it.
func TestSaveConfigSurvivesAUserEntryThatIsNotAMapping(t *testing.T) {
	path := writeTestConfig(t, `rbac:
  roles:
    user:
      permissions:
        - view
  users:
    ghost:
    authpf-user1:
      password: "$2a$12$zyxwvutsrqponmlkjihg"
      role: user
      userId: 1001
      userIp: 192.168.0.10
`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig() = %v", err)
	}

	if got := rbacUserSection(t, path, "authpf-user1")["userIp"]; got != "192.168.0.10" {
		t.Errorf("userIp of the user beside it = %v, want 192.168.0.10", got)
	}
	if _, err := loadConfig(path); err != nil {
		t.Errorf("the saved file no longer parses: %v", err)
	}
}

// What that entry means for an operator, though, is a refusal rather than a write: an entry with
// nothing under it decodes to a user with no role, and the write gate will not produce a file
// whose user names a role the file does not define. Checked separately because the save itself has
// to stay total, and the gate is what keeps the unusable result off the disk.
func TestUserCommandsRefuseAFileWithAUserThatHasNoEntry(t *testing.T) {
	path := writeTestConfig(t, `rbac:
  roles:
    user:
      permissions:
        - view
  users:
    ghost:
    authpf-user1:
      password: "$2a$12$zyxwvutsrqponmlkjihg"
      role: user
      userId: 1001
      userIp: 192.168.0.10
`)
	before := fileContents(t, path)

	if err := runUserCommand(t, userModifyCmd, "-c", path, "-u", "authpf-user1", "-p", "Passw0rd1"); err == nil {
		t.Fatal("a command succeeded on a file whose user has no role")
	}
	if after := fileContents(t, path); after != before {
		t.Errorf("the refused command changed the file:\n%s", after)
	}
}

// An empty file holds nothing to overlay onto, and rbac alone is a config the server refuses to
// start from. saveConfig has to report that instead of panicking on an assignment into a nil map.
// No command reaches it today - the write gate refuses a file with no users first - so this pins
// the function's own contract, which its comment describes as defence in depth.
func TestSaveConfigRefusesAFileWithoutAnySections(t *testing.T) {
	path := writeTestConfig(t, "# nothing here yet\n")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}
	cfg.Rbac.Users = map[string]config.ConfigFileRbacUsers{"carol": {Password: "hash", Role: "user"}}

	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("saveConfig() wrote a file that has no sections to update")
	}
	if got := fileContents(t, path); got != "# nothing here yet\n" {
		t.Errorf("the refused file changed:\n%s", got)
	}
}

// A numeric- or bool-shaped key turns a whole YAML mapping into a map[interface{}]interface{} when
// yaml.v3 decodes it, and such keys are reachable in a hand-edited file: a user named only with
// digits satisfies the server's own username pattern, and "2024: audited" is the sort of note an
// operator leaves behind. Reading just the string-keyed shape would see no rbac section at all and
// write one fresh - the exact loss this function exists to prevent - so both shapes have to be
// carried. The keys come back quoted, which is the same file to the server: its typed decode keys
// those maps by string too, and validateForServer runs on that decode.
func TestSaveConfigKeepsASubtreeWhoseKeysAreNotStrings(t *testing.T) {
	path := writeTestConfig(t, `rbac:
  2024: audited by hand
  roles:
    admins:
      description: read-only auditor
      permissions:
        - view
  users:
    1001:
      password: "$2a$12$abcdefghijklmnopqrstuv"
      role: admins
      userIp: 192.0.2.7
      pfTable: authpf_admins
`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() = %v", err)
	}
	cfg.Rbac.Users["newcomer"] = config.ConfigFileRbacUsers{Password: "hash", Role: "admins"}

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig() = %v", err)
	}

	after, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the saved file no longer parses: %v", err)
	}
	if got := after.Rbac.Users["1001"].UserIP; got != "192.0.2.7" {
		t.Errorf("userIp of the digit-named user = %q, want 192.0.2.7", got)
	}
	if got := after.Rbac.Users["1001"].PfTable; got != "authpf_admins" {
		t.Errorf("pfTable of the digit-named user = %q, want authpf_admins", got)
	}
	if got := rbacSection(t, path)["2024"]; got != "audited by hand" {
		t.Errorf("the note under rbac = %v, want it kept", got)
	}
	if _, ok := after.Rbac.Users["2024"]; ok {
		t.Error("the note under rbac was read as a user")
	}

	// The written file is still one the server would accept and these commands would write again.
	if err := validateForServer(after); err != nil {
		t.Errorf("the saved file fails the write gate: %v", err)
	}
}

// The same guarantee one level up, through the commands an operator runs. The realistic case is
// not an adversary but a documented account addition or password rotation that quietly rewrites
// every other account's policy, so each command is run against an unrelated account here.
func TestUserCommandsKeepThePolicyFieldsOfUntouchedUsers(t *testing.T) {
	cases := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"create", userCreateCmd, []string{"-u", "carol", "-p", "Passw0rd1", "-r", "user", "-i", "3001"}},
		{"modify", userModifyCmd, []string{"-u", "authpf-admin", "-p", "Passw0rd1"}},
		{"delete", userDeleteCmd, []string{"-u", "authpf-admin"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, policyConfig)

			if err := runUserCommand(t, tc.cmd, append([]string{"-c", path}, tc.args...)...); err != nil {
				t.Fatalf("user %s failed: %v", tc.name, err)
			}

			after, err := loadConfig(path)
			if err != nil {
				t.Fatalf("the saved file no longer parses: %v", err)
			}

			user1 := after.Rbac.Users["authpf-user1"]
			if user1.UserIP != "192.168.0.10" {
				t.Errorf("userIp = %q, want the pinned 192.168.0.10", user1.UserIP)
			}
			wantMacros := map[string]string{"server_1_addr": "10.127.2.1", "server_1_port": "22"}
			if !maps.Equal(user1.Macros, wantMacros) {
				t.Errorf("macros = %v, want %v", user1.Macros, wantMacros)
			}
			if admin, ok := after.Rbac.Users["authpf-admin"]; ok && admin.PfTable != "authpf_admins" {
				t.Errorf("pfTable of authpf-admin = %q, want authpf_admins", admin.PfTable)
			}
			if got := rbacUserSection(t, path, "authpf-user1")["futureField"]; got == nil {
				t.Error("an unmodelled key under rbac.users was written away")
			}
		})
	}
}

// assertNoStrayFiles wants the directory to hold exactly the named entries, so no case leaves
// a half-written or backup file beside the config.
func assertNoStrayFiles(t *testing.T, dir string, want ...string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != len(want) {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("%s holds %v, want only %v", dir, names, want)
	}
}

// The write gate next: what the server would refuse to start from, measured on the result of a
// change rather than on the change itself, because that result is the file that gets written.

// One admin user and two roles: enough to exercise every rule, and the shape a real
// /usr/local/etc/authpf-api.conf starts from.
const rbacUsersConfig = `rbac:
  roles:
    user:
      permissions:
        - view
    admin:
      permissions:
        - view
        - modify
  users:
    authpf-admin:
      password: "$2a$12$abcdefghijklmnopqrstuv"
      role: admin
      userId: 1000
`

func TestValidateForServer(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErr  string
		wantOkay bool
	}{
		{
			name:     "file as the server wants it",
			content:  rbacUsersConfig,
			wantOkay: true,
		},
		{
			name: "nobody left",
			content: `rbac:
  roles:
    user: {}
  users: {}`,
			wantErr: "no users configured",
		},
		{
			name: "dotted username",
			content: `rbac:
  roles:
    user: {}
  users:
    john.doe:
      role: user
      password: x`,
			wantErr: `invalid username "john.doe"`,
		},
		{
			name: "username with a space",
			content: `rbac:
  roles:
    user: {}
  users:
    "john doe":
      role: user
      password: x`,
			wantErr: `invalid username "john doe"`,
		},
		{
			name: "role that does not exist",
			content: `rbac:
  roles:
    user: {}
  users:
    alice:
      role: admine
      password: x`,
			wantErr: `unknown role "admine"`,
		},
		{
			name: "role left empty",
			content: `rbac:
  roles:
    user: {}
  users:
    alice:
      role: ""
      password: x`,
			wantErr: "role: must not be empty",
		},
		{
			name: "two users sharing a userId",
			content: `rbac:
  roles:
    user: {}
  users:
    alice:
      role: user
      userId: 1000
      password: x
    bob:
      role: user
      userId: 1000
      password: y`,
			wantErr: "duplicate userId 1000",
		},
		{
			name: "negative userId",
			content: `rbac:
  roles:
    user: {}
  users:
    alice:
      role: user
      userId: -1
      password: x`,
			wantErr: "must not be negative",
		},
		{
			name: "several users without a userId",
			content: `rbac:
  roles:
    user: {}
  users:
    alice:
      role: user
      password: x
    bob:
      role: user
      password: y`,
			wantOkay: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Through loadConfig, so a fixture that does not parse cannot pass as a
			// rejected write.
			cfg, err := loadConfig(writeTestConfig(t, tt.content))
			if err != nil {
				t.Fatalf("test fixture does not load: %v", err)
			}

			err = validateForServer(cfg)
			switch {
			case tt.wantOkay && err != nil:
				t.Fatalf("valid rbac.users section was rejected: %v", err)
			case !tt.wantOkay && err == nil:
				t.Fatalf("broken rbac.users section was accepted, wanted: %s", tt.wantErr)
			case !tt.wantOkay && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error is %q, wanted it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// The 255 character cap is the one rule a table of literals cannot pin down, so the
// boundary gets measured.
func TestValidateForServerUsernameLengthBoundary(t *testing.T) {
	cfg, err := loadConfig(writeTestConfig(t, rbacUsersConfig))
	if err != nil {
		t.Fatal(err)
	}

	user := config.ConfigFileRbacUsers{Role: "user", Password: "x"}

	for _, length := range []int{serverMaxUsernameLength, serverMaxUsernameLength + 1} {
		name := strings.Repeat("a", length)
		cfg.Rbac.Users[name] = user
		err := validateForServer(cfg)

		if length > serverMaxUsernameLength && err == nil {
			t.Errorf("a %d character username was accepted", length)
		}
		if length == serverMaxUsernameLength && err != nil {
			t.Errorf("a %d character username was refused: %v", length, err)
		}

		delete(cfg.Rbac.Users, name)
	}
}

// The four rules below are the report's proofs of concept, run through the command handlers:
// what matters is not that a helper notices the bad value, but that the file on disk is
// still the one the server can read.

func TestUserCreateRefusesWhatTheServerWouldReject(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "dotted username",
			args:    []string{"-u", "john.doe", "-p", "Passw0rd1", "-r", "user"},
			wantErr: `invalid username "john.doe"`,
		},
		{
			name:    "username with a space",
			args:    []string{"-u", "john doe", "-p", "Passw0rd1", "-r", "user"},
			wantErr: `invalid username "john doe"`,
		},
		{
			name:    "role typed wrong",
			args:    []string{"-u", "mallory", "-p", "Passw0rd1", "-r", "admine"},
			wantErr: `unknown role "admine"`,
		},
		{
			name:    "no role at all",
			args:    []string{"-u", "mallory", "-p", "Passw0rd1", "-r", ""},
			wantErr: "role: must not be empty",
		},
		{
			name:    "userId already taken",
			args:    []string{"-u", "mallory", "-p", "Passw0rd1", "-r", "user", "-i", "1000"},
			wantErr: "duplicate userId 1000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, rbacUsersConfig)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			args := append([]string{"-c", path}, tc.args...)
			err = runUserCommand(t, userCreateCmd, args...)
			if err == nil {
				t.Fatalf("user create accepted a %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error is %q, wanted it to contain %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "server would reject") {
				t.Errorf("error %q does not say what was refused", err)
			}

			assertFileUnchanged(t, path, before)
		})
	}
}

// A valid user must still get through: a gate that rejects everything would look just as
// healthy in the failing tests above.
func TestUserCreateStillAcceptsAValidUser(t *testing.T) {
	path := writeTestConfig(t, rbacUsersConfig)

	err := runUserCommand(t, userCreateCmd,
		"-c", path, "-u", "carol", "-p", "Passw0rd1", "-r", "user", "-i", "3001",
	)
	if err != nil {
		t.Fatalf("valid user create was refused: %v", err)
	}

	after, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Rbac.Users["carol"]; !ok {
		t.Error("carol is missing from the saved config")
	}
	if err := validateForServer(after); err != nil {
		t.Errorf("the saved file is something the server would reject: %v", err)
	}
}

func TestUserModifyRefusesAUnknownRole(t *testing.T) {
	path := writeTestConfig(t, rbacUsersConfig)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = runUserCommand(t, userModifyCmd, "-c", path, "-u", "authpf-admin", "-r", "admine")
	if err == nil {
		t.Fatal("user modify accepted a role that does not exist")
	}
	if !strings.Contains(err.Error(), `unknown role "admine"`) {
		t.Errorf("error is %q", err)
	}

	assertFileUnchanged(t, path, before)
}

// Deleting the last user is the quietest one of the lot: the CLI reports success, the
// file is well formed YAML, and the server simply never comes back.
func TestUserDeleteRefusesToRemoveTheLastUser(t *testing.T) {
	path := writeTestConfig(t, rbacUsersConfig)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = runUserCommand(t, userDeleteCmd, "-c", path, "-u", "authpf-admin")
	if err == nil {
		t.Fatal("user delete accepted removing the only user")
	}
	if !strings.Contains(err.Error(), "no users configured") {
		t.Errorf("error is %q", err)
	}

	assertFileUnchanged(t, path, before)
}

// ... and the repair path stays open: a file an older CLI broke can be put right with
// delete plus create, because both are checked against the result they would leave behind.
func TestUserDeleteOfOneUserOfTwoStillWorks(t *testing.T) {
	path := writeTestConfig(t, rbacUsersConfig+`    operator:
      password: "$2a$12$zyxwvutsrqponmlkjihg"
      role: user
      userId: 2000
`)

	err := runUserCommand(t, userDeleteCmd, "-c", path, "-u", "operator")
	if err != nil {
		t.Fatalf("deleting one of two users was refused: %v", err)
	}

	after, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Rbac.Users["operator"]; ok {
		t.Error("operator is still in the saved config")
	}
	if _, ok := after.Rbac.Users["authpf-admin"]; !ok {
		t.Error("authpf-admin disappeared from the saved config")
	}
}

// writeTestConfig puts a config file in a test directory and returns its path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "authpf-api.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	return path
}

// assertFileUnchanged is the whole point of the guard: after a refusal, the file must be the
// bytes it was, because those are the last ones the server can still start from.
func assertFileUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the config back: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("config was written despite the refusal:\n%s", after)
	}
}

// runUserCommand parses args the way cobra would and calls the handler behind cmd, so the
// assertions cover the same code path the binary takes. Every flag is reset to its default
// first: the three commands share one process here, and a value left over from the previous
// case would silently join this one.
func runUserCommand(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()

	for _, name := range []string{"username", "password", "role", "user-id", "config-path"} {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			continue
		}
		if err := flag.Value.Set(flag.DefValue); err != nil {
			t.Fatalf("resetting --%s: %v", name, err)
		}
		flag.Changed = false
	}

	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}

	// The handlers report progress on stdout, which is not what these tests assert on.
	var err error
	captureStdout(t, func() {
		err = cmd.RunE(cmd, nil)
	})

	return err
}
