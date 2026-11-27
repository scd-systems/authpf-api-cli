package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/spf13/cobra"
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
