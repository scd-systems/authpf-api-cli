#!/bin/sh
# End-to-end tests for authpf-api-cli: the built binary as a subprocess against
# tests/mock_server.py.
#
# What only shows up here is the wiring around a command: the exit code and the single
# error line main.go is responsible for, the config file and the AUTHPF_ environment, and
# the bytes that actually leave the process. The injection sinks themselves are covered in
# cmd/, in process.
#
# Against a real server, run tests/e2e_remote.sh instead.
#
# Run: make test-e2e       (needs go and python3)
set -eu

repo=$(CDPATH=0 cd "$(dirname "$0")/.." && pwd)
. "$repo/tests/lib.sh"

tmp=$(mktemp -d)
srv_pid=''
cleanup() {
  [ -z "$srv_pid" ] || kill "$srv_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

for tool in go python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "needs $tool" >&2; exit 1; }
done

# A hung client would otherwise hang the suite: the oversized response never terminates.
TIMEOUT=''
command -v timeout >/dev/null 2>&1 && TIMEOUT='timeout 30'

bin=$tmp/authpf-api-cli
home=$tmp/home
mkdir -p "$home"
build_cli "$repo" "$bin"

port=$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])')
python3 "$repo/tests/mock_server.py" "$port" >"$tmp/server.log" 2>&1 &
srv_pid=$!
sleep 1
kill -0 "$srv_pid" 2>/dev/null || { echo "mock server did not start:" >&2; cat "$tmp/server.log" >&2; exit 1; }

server="http://127.0.0.1:$port"
config=$tmp/config.yaml
printf 'api:\n  server: %s\n  username: alice\n  password: "Passw0rd_1"\n  authpf:\n    username: bob\n' \
  "$server" >"$config"

# The same config with a path prefix, which the server answers with an endless 9 MB body.
config_huge=$tmp/config-huge.yaml
printf 'api:\n  server: %s/huge\n' "$server" >"$config_huge"

# A token written into the config file with escape sequences in it, the way the report left
# it behind after a login against a hostile server. \u001b is how YAML spells ESC.
config_escaped=$tmp/config-escaped-token.yaml
printf 'api:\n  server: %s\n  token: "\\u001b]0;TITLEPWN\\u0007abcdefghij"\n' \
  "$server" >"$config_escaped"

# The report's first proof of concept, end to end: an OSC sequence arrives inside an anchor
# name, and an anchor entry is null, which used to take the process down.
run "--all lists a null anchor without escaping the terminal" 0 "$config" validtoken0123456789 \
  authpf status --all
check_has "Total active anchors: 2"
check_has '␣]0;PWNED-TITLE␣'
# U+009B as UTF-8: no single byte in the ASCII control range, so it needs its own check.
check_has 'carol␣[2J'
check_lacks "$(printf '\302\233')"
check_clean
check_no_panic
done_case

# The error text taken from a response body: one line, neutralised, and no line that only
# looks like output of the tool itself.
run "a 403 body does not reach the terminal" 1 "$config" validtoken0123456789 \
  authpf activate
check_has "❌ Error: activate failed with status 403"
check_has "␣]0;root@core-gw␣"
check_lacks "Usage:"
check_one_line
check_clean
check_no_panic
done_case

# A token shorter than the 10 characters the tool shows used to panic on the slice.
run "a four character token is shown" 0 "$config" AB12 auth token
check_is "Current Token: AB12...."
check_no_panic
done_case

# Same escape sequences, this time stored in the config file and echoed by auth token.
run "a stored token with escapes stays on screen" 0 "$config_escaped" "" auth token
check_is "Current Token: ␣]0;TITLEP...."
check_clean
check_no_panic
done_case

# An endpoint must not decide how much the client buffers.
run "a 9 MB response is refused" 1 "$config_huge" validtoken0123456789 auth status
check_has "exceeds the 8 MB limit"
check_clean
check_no_panic
done_case

# The other direction: an escape sequence in the token must not leave through a header.
run "escapes in the token are not sent as a header" 1 "$config" \
  "$(printf '\033]0;PWNED\007abcdefghij')" auth status
check_has "Authorization"
check_clean
check_no_panic
done_case

# The counterpart of the quiet error path: a flag that was never typed right keeps its
# usage block, so SilenceUsage stays unset.
run "an unknown flag still explains itself" 1 "$config" "" --definitely-not-a-flag
check_has "Usage:"
check_no_panic
done_case

# auth login saves a live bearer token, so it may not leave that file readable by
# anybody else - not even when the directory and both files already existed loose, which is
# what a home restore or an older release leaves behind.
home_saved=$home
home=$tmp/home-loose
mkdir -p "$home/.authpf-api-cli"
chmod 755 "$home/.authpf-api-cli"
printf 'api:\n  token: stale\n' >"$home/.authpf-api-cli/config.yaml"
printf 'username: nobody\npassword: none\n' >"$home/.authpf-api-cli/credentials.yaml"
chmod 666 "$home/.authpf-api-cli/config.yaml" "$home/.authpf-api-cli/credentials.yaml"
config_login=$tmp/config-login.yaml
printf 'api:\n  server: %s/allow\n  username: alice\n  password: "Passw0rd_1"\n' \
  "$server" >"$config_login"
run "auth login saves its token owner-only" 0 "$config_login" "" auth login
check_has "Token saved to config file"
check_no_panic
for file in config.yaml credentials.yaml; do
  mode=$(file_mode "$home/.authpf-api-cli/$file")
  [ "$mode" = 600 ] || fail ".authpf-api-cli/$file is mode $mode, want 600"
done
home=$home_saved
done_case

# -p asks for the password at the terminal, so the secret never sits in the process argument
# vector, where every user logged in would read it out of /proc/<pid>/cmdline. Two things
# follow that are reachable without a terminal in front of the test run: a stdin nobody can
# type into has to be refused instead of waited for, and a password still given as a value
# has to be refused without being printed back into the terminal or the CI log.
run "auth login -p refuses a stdin nobody can type into" 1 "$config" "" auth login -p
check_has "AUTHPF_API_PASSWORD"
check_no_panic
done_case

run "auth login -p with a password next to it is refused" 1 "$config" "" auth login -p 'Passw0rd_1'
check_has "takes no arguments"
check_lacks "Passw0rd_1"
check_no_panic
done_case

# The status symbols are decoration: every line they lead says in words what it says in
# colour. A locale that declares a codeset older than Unicode has to be given those words
# on their own, because the three bytes of a checkmark decode there into "Ã´Â¸Ã®".
# This case cannot go through run(), which builds the child's environment of its own.
out=$(env -i HOME="$home" LC_ALL=C "$bin" auth login -p </dev/null 2>&1) && got=0 || got=$?
fails_here=0
printf '  %-56s exit %s' "a locale without UTF-8 is given plain words" "$got"
[ "$got" = 1 ] || fail "wanted exit code 1"
check_has "Error: no terminal to type the password into"
check_lacks "❌"
check_no_panic
done_case

# -c/--config-path says which server config to edit, so what the tool accepts there
# is all that stands between the command and somebody else's file. Everything below runs
# unprivileged in a scratch directory: an arbitrary destination is legitimate operator work and
# stays possible, a link pointing somewhere else is not.
srv=$tmp/server-side
mkdir -p "$srv"
conf=$srv/authpf-api.conf
printf 'server:\n  jwtSecret: NOT-YOURS\nrbac:\n  roles:\n    admins:\n      id: 1000\n      anchor: "authpf"\n  users: {}\n' >"$conf"
chmod 600 "$conf"

run "user create edits the file -c names" 0 "" "" user create -c "$conf" -u operator -p pw12345 -r admins
check_has "User created successfully"
check_no_panic
check_lacks "NOT-YOURS"
case $(cat "$conf") in
  *operator*) ;;
  *) fail "the new user is missing from the config" ;;
esac
# The file is rewritten where it is, so neither its mode nor the sections the CLI does not
# know about may change.
[ "$(file_mode "$conf")" = 600 ] || fail "mode after save is $(file_mode "$conf"), want 600"
grep -q "NOT-YOURS" "$conf" || fail "the server section was dropped from the config"
[ "$(ls -A "$srv" | wc -l | tr -d ' ')" = 1 ] || fail "the save left a stray file next to the config"
done_case

victim=$srv/victim.conf
planted=$srv/planted-link
printf 'server:\n  jwtSecret: NOT-YOURS\n' >"$victim"
chmod 600 "$victim"
ln -s "$victim" "$planted"
run "a config path that is a symlink is refused" 1 "" "" user list -c "$planted"
check_has "refusing to follow it"
check_lacks "jwtSecret"
check_no_panic
grep -q "NOT-YOURS" "$victim" || fail "the link target lost its content"
case $(ls -l "$planted") in
  *"$victim"*) ;;
  *) fail "the planted link itself was replaced" ;;
esac
done_case

run "user create refuses to save through a symlink" 1 "" "" user create -c "$planted" -u intruder -p pw12345 -r admins
check_has "refusing to follow it"
check_lacks "User created successfully"
check_no_panic
if grep -q "intruder" "$victim"; then
  fail "a user was injected into the file behind the symlink"
fi
done_case

# A fifo in that position used to leave the command waiting for a writer that never comes.
if command -v mkfifo >/dev/null 2>&1; then
  mkfifo "$srv/fifo-conf"
  run "a fifo as config path is refused, not waited on" 1 "" "" user list -c "$srv/fifo-conf"
  check_has "not a regular file"
  check_no_panic
  done_case
else
  skip "a fifo as config path is refused, not waited on" "mkfifo unavailable"
fi

# nothing but the CLI stands between a typo and a server that stays down, since
# the server refuses to start on an rbac.users section it does not accept and the file has
# already been rewritten by then. What the command rejects must therefore leave the file
# exactly as it was: those are the last bytes the server can still start from.
cp "$conf" "$tmp/conf.before"
run "user create refuses a username the server would reject" 1 "" "" user create -c "$conf" -u john.doe -p pw12345 -r admins
check_has "server would reject"
check_has 'invalid username "john.doe"'
check_error_once
check_lacks "Usage:"
check_no_panic
if grep -q john.doe "$conf"; then
  fail "the rejected username was written to the config"
fi
cmp -s "$tmp/conf.before" "$conf" || fail "a refused write still changed the config"
done_case

run "user delete refuses to remove the last user" 1 "" "" user delete -c "$conf" -u operator
check_has "no users configured"
check_lacks "User deleted successfully"
check_no_panic
grep -q operator "$conf" || fail "the last user was deleted from the config"
done_case

# The same two commands with a valid result are ordinary work, so a gate that refused
# everything could not pass these lines either.
run "user create adds a second user" 0 "" "" user create -c "$conf" -u second -p pw12345 -r admins
check_has "User created successfully"
check_no_panic
done_case

run "user delete removes one user of two" 0 "" "" user delete -c "$conf" -u second
check_has "User deleted successfully"
check_no_panic
grep -q operator "$conf" || fail "the user that stayed was lost"
done_case

# the save rebuilds the whole rbac section, so every key in it that this tool does not
# edit has to come back out of the file unchanged. userIp pins which address an anchor is bound
# to, macros are the definitions its rules file is loaded with, and pfTable picks the pf table the
# address is added to - all three are handed to pfctl by the server, so writing them away changed
# the firewall policy of accounts no command had named, with exit code 0.
pconf=$srv/policy.conf
printf 'rbac:\n  roles:\n    admins:\n      description: read-only auditor\n      permissions:\n        - view_own_rules\n  users:\n    pinned:\n      password: "$2a$12$abcdefghijklmnopqrstuv"\n      role: admins\n      userId: 1001\n      userIp: 192.0.2.7\n      pfTable: authpf_admins\n      macros:\n        pinned_port: 8443\n' >"$pconf"
chmod 600 "$pconf"
run "user create keeps the policy of the accounts it did not touch" 0 "" "" user create -c "$pconf" -u newcomer -p pw12345 -r admins
check_has "User created successfully"
check_no_panic
for want in 'userIp: 192.0.2.7' 'pfTable: authpf_admins' 'pinned_port: 8443'; do
  grep -q "$want" "$pconf" || fail "the save dropped $want"
done
grep -q 'description: read-only auditor' "$pconf" || fail "the save dropped a role key this tool does not model"
done_case

# --version is the command reached for while finding out why a server is down, so it may not
# depend on that server answering: one second, then the CLI's own version and a note.
config_slow=$tmp/config-slow.yaml
printf 'api:\n  server: %s/slow\n' "$server" >"$config_slow"

run "--version reports both sides when the server answers" 0 "$config" "" --version
check_has '"client_version"'
check_has '"server_version": "1.0"'
check_lacks '"server_note"'
check_no_panic
done_case

version_start=$(date +%s)
run "--version does not wait for a server that is late" 0 "$config_slow" "" --version
check_has '"server_note"'
check_lacks '"server_version"'
check_no_panic
version_took=$(( $(date +%s) - version_start ))
[ "$version_took" -le 5 ] || fail "the version probe waited ${version_took}s"
done_case

suite_result
