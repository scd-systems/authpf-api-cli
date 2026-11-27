# Shared helpers for the shell suites in tests/. Sourced, never run directly.
#
# The caller sets: bin (the CLI to run), home (HOME for the child), TIMEOUT (may be empty).

fails=0
fails_here=0
cases=0
# Control characters a terminal would act on, as a grep bracket range. The line feeds
# between the tool's own lines are not part of it.
ctls=$(printf '\001-\010\013\014\016-\037\177')

fail() {
  printf '    %s\n' "$1"
  fails_here=$((fails_here + 1))
}

# build_cli REPO OUT
build_cli() {
  ( CDPATH=0; cd "$1" && go build -o "$2" . )
}

# cli CONFIGFILE TOKEN ARGS...  An empty CONFIGFILE means the default
# ~/.authpf-api-cli/config.yaml of the child, which is where auth login saves its token.
cli() {
  cfg=$1; shift
  tok=$1; shift
  extra=''
  if [ -n "$cfg" ]; then
    extra="--config $cfg"
  fi
  # env -i so nothing of the developer's own AUTHPF_ configuration can answer a test. The
  # password travels in the config file, never on the command line, where anyone logged in
  # could read it out of the process list.
  # shortcut: a config path with a space would need a real array here
  # shellcheck disable=SC2086
  $TIMEOUT env -i HOME="$home" AUTHPF_API_TOKEN="$tok" "$bin" $extra "$@"
}

# run NAME WANT_CODE CONFIGFILE TOKEN ARGS...
run() {
  name=$1; want=$2; cfg=$3; tok=$4; shift 4
  # stdin comes from /dev/null, never from the terminal running the suite: a command that
  # wants typing has to refuse that situation out loud, and a command that hangs on it has
  # to fail this case instead of holding the whole suite until TIMEOUT.
  out=$(cli "$cfg" "$tok" "$@" </dev/null 2>&1) && got=0 || got=$?
  fails_here=0
  printf '  %-56s exit %s' "$name" "$got"
  [ "$got" = "$want" ] || fail "wanted exit code $want"
}

skip() {
  printf '  %-56s skipped (%s)\n' "$1" "$2"
}

check_has() {
  case $out in *"$1"*) ;; *) fail "output lacks: $1" ;; esac
}

check_is() {
  [ "$out" = "$1" ] || fail "wanted exactly: $1"
}

check_lacks() {
  case $out in *"$1"*) fail "output must not contain: $1" ;; esac
}

check_clean() {
  if printf '%s' "$out" | LC_ALL=C grep -q "[$ctls]"; then
    fail "output carries terminal control characters: $(printf '%s' "$out" | od -An -c | tr -s ' ' | head -2)"
  fi
}

check_one_line() {
  n=$(printf '%s\n' "$out" | wc -l | tr -d ' ')
  [ "$n" = 1 ] || fail "wanted a single line of output, got $n"
}

# A command that failed may have printed progress first, so count the error lines rather
# than the whole output.
check_error_once() {
  n=$(printf '%s\n' "$out" | grep -c '^❌ Error: ')
  [ "$n" = 1 ] || fail "wanted exactly one error line, got $n"
}

# file_mode PATH - octal mode of a file, on GNU and BSD stat alike.
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo missing
}

check_no_panic() {
  case $out in
    *panic:* | *"goroutine "*) fail "the CLI crashed instead of reporting: $(printf '%s\n' "$out" | head -2)" ;;
  esac
}

done_case() {
  cases=$((cases + 1))
  if [ "$fails_here" = 0 ]; then
    printf '  ok\n'
  else
    printf '  FAILED\n'
    fails=$((fails + 1))
  fi
}

suite_result() {
  if [ "$fails" -gt 0 ]; then
    printf '\n%d of %d cases failed\n' "$fails" "$cases" >&2
    exit 1
  fi
  printf '\nall %d cases passed\n' "$cases"
}
