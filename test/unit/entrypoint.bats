#!/usr/bin/env bats

setup() {
  load '../test_helper/bats-support/load'
  load '../test_helper/bats-assert/load'

  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  MOCK_DIR="$(mktemp -d)"

  export MOCK_ARGS_FILE="$MOCK_DIR/openconnect_args"
  export MOCK_STDIN_FILE="$MOCK_DIR/openconnect_stdin"

  cat > "$MOCK_DIR/openconnect" << 'MOCK'
#!/bin/sh
echo "$@" > "$MOCK_ARGS_FILE"
if [ -t 0 ]; then
  : > "$MOCK_STDIN_FILE"
else
  cat > "$MOCK_STDIN_FILE"
fi
exit 0
MOCK
  chmod +x "$MOCK_DIR/openconnect"
  export PATH="$MOCK_DIR:$PATH"

  # Extract the run() function from entrypoint.sh, renamed to vpn_run to avoid
  # conflicting with BATS's built-in run command
  eval "$(sed -n '/^run () {/,/^}/p' "$PROJECT_ROOT/build/entrypoint.sh" | sed 's/^run ()/vpn_run()/')"
  eval "$(sed -n '/^run_with_retries()/,/^}/p' "$PROJECT_ROOT/build/entrypoint.sh")"

  cat > "$MOCK_DIR/jq" << 'MOCK'
#!/bin/sh
if [ "$1" = "-r" ] && [ "$2" = ".cookie" ]; then
  cat "$3" | sed -n 's/.*"cookie": *"\([^"]*\)".*/\1/p'
fi
MOCK
  chmod +x "$MOCK_DIR/jq"

  export OPENCONNECT_USER="testuser"
  export OPENCONNECT_URL="vpn.example.com"
  unset OPENCONNECT_PASSWORD
  unset OPENCONNECT_MFA_CODE
  unset OPENCONNECT_MFA_FORMAT
  unset OPENCONNECT_OPTIONS
  unset OPENCONNECT_COOKIE
  unset OPENCONNECT_COOKIE_FILE
  unset VPN_SPLIT
  unset VPN_ROUTES
  unset OPENCONNECT_TOTP_SECRET
  unset OPENCONNECT_MFA_FROM_TOTP

  export OATHTOOL_COUNTER_FILE="$MOCK_DIR/oathtool_counter"
  echo 0 > "$OATHTOOL_COUNTER_FILE"
  cat > "$MOCK_DIR/oathtool" << 'MOCK'
#!/bin/sh
n=$(cat "$OATHTOOL_COUNTER_FILE")
n=$((n + 1))
echo "$n" > "$OATHTOOL_COUNTER_FILE"
printf '12345%s\n' "$n"
MOCK
  chmod +x "$MOCK_DIR/oathtool"
}

teardown() {
  rm -rf "$MOCK_DIR"
}

# Compare bytes, including the final newline, rather than trimming stdin with
# command substitution.
assert_stdin_equals() {
  printf '%s\n' "$1" > "$MOCK_DIR/expected_stdin"
  run cmp "$MOCK_DIR/expected_stdin" "$MOCK_STDIN_FILE"
  assert_success
}

# --- Password modes ---

@test "interactive mode when password is not set" {
  run vpn_run
  assert_success
  assert_output --partial "Password not set. Prompting for password..."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser vpn.example.com"
}

@test "password-only mode pipes password via --passwd-on-stdin" {
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Password detected. Starting OpenConnect."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser --passwd-on-stdin vpn.example.com"

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "secret123"
}

@test "default MFA format pipes password and MFA code on separate lines" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"

  run vpn_run
  assert_success
  assert_output --partial "Password and MFA detected."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser --passwd-on-stdin vpn.example.com"

  expected="$(printf 'secret123\n654321')"
  assert_stdin_equals "$expected"
}

@test "explicit separate MFA format preserves two-line input" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"
  export OPENCONNECT_MFA_FORMAT="separate"

  run vpn_run
  assert_success
  assert_stdin_equals "$(printf 'secret123\n654321')"
}

@test "comma MFA format sends exactly password,654321 on one line" {
  export OPENCONNECT_PASSWORD="password"
  export OPENCONNECT_MFA_CODE="654321"
  export OPENCONNECT_MFA_FORMAT="comma"
  export OPENCONNECT_OPTIONS="--protocol=gp"

  run vpn_run
  assert_success
  refute_output --partial "$OPENCONNECT_PASSWORD"
  refute_output --partial "$OPENCONNECT_MFA_CODE"
  assert_equal "$(cat "$MOCK_ARGS_FILE")" "--protocol=gp -u testuser --passwd-on-stdin vpn.example.com"
  assert_stdin_equals "password,654321"
}

@test "MFA formats preserve special characters in passwords" {
  export OPENCONNECT_PASSWORD='-n\c p@ss\word %s "quoted" $HOME $(literal) `literal` * ; & | ,'
  export OPENCONNECT_MFA_CODE="654321"

  for format in separate comma; do
    export OPENCONNECT_MFA_FORMAT="$format"
    run vpn_run
    assert_success
    refute_output --partial "$OPENCONNECT_PASSWORD"
    refute_output --partial "$OPENCONNECT_MFA_CODE"

    if [ "$format" = "comma" ]; then
      assert_stdin_equals "$OPENCONNECT_PASSWORD,654321"
    else
      assert_stdin_equals "$OPENCONNECT_PASSWORD
654321"
    fi
  done
}

@test "comma MFA format preserves password-only mode" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_FORMAT="comma"

  run vpn_run
  assert_success
  assert_output --partial "Password detected. Starting OpenConnect."
  assert_equal "$(cat "$MOCK_ARGS_FILE")" "-u testuser --passwd-on-stdin vpn.example.com"
  assert_stdin_equals "secret123"
}

@test "comma MFA format preserves interactive password mode" {
  export OPENCONNECT_MFA_FORMAT="comma"

  run vpn_run
  assert_success
  assert_output --partial "Password not set. Prompting for password..."
  assert_equal "$(cat "$MOCK_ARGS_FILE")" "-u testuser vpn.example.com"
}

@test "invalid MFA formats are rejected before starting OpenConnect" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"

  for format in invalid COMMA 'comma ' 'separate,comma'; do
    run env OPENCONNECT_MFA_FORMAT="$format" sh "$PROJECT_ROOT/build/entrypoint.sh"
    assert_failure 1
    assert_output "FATAL: OPENCONNECT_MFA_FORMAT must be separate or comma"
    [ ! -e "$MOCK_ARGS_FILE" ]
    [ ! -e "$MOCK_STDIN_FILE" ]
  done
}

# --- TOTP auto-generation ---

@test "TOTP secret generates MFA code automatically" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"

  run vpn_run
  assert_success
  assert_output --partial "TOTP code generated from secret."
  assert_output --partial "Password and MFA detected."

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  expected="$(printf 'secret123\n123451')"
  assert_equal "$stdin_content" "$expected"
}

@test "TOTP secret generates MFA code in comma format without logging credentials" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"
  export OPENCONNECT_MFA_FORMAT="comma"

  run vpn_run
  assert_success
  assert_output --partial "TOTP code generated from secret."
  refute_output --partial "$OPENCONNECT_PASSWORD"
  refute_output --partial "$OPENCONNECT_TOTP_SECRET"
  refute_output --partial "123451"
  assert_stdin_equals "secret123,123451"
}

@test "comma TOTP is refreshed on retries in the same shell" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"
  export OPENCONNECT_MFA_FORMAT="comma"
  export MAX_RECONNECT_ATTEMPTS=1
  export RECONNECT_DELAY=0
  export MOCK_ATTEMPT_FILE="$MOCK_DIR/attempts"
  echo 0 > "$MOCK_ATTEMPT_FILE"

  cat > "$MOCK_DIR/openconnect" << 'MOCK'
#!/bin/sh
attempt=$(cat "$MOCK_ATTEMPT_FILE")
attempt=$((attempt + 1))
printf '%s\n' "$attempt" > "$MOCK_ATTEMPT_FILE"
cat > "$MOCK_STDIN_FILE.$attempt"
[ "$attempt" -ge 2 ]
MOCK

  run run_with_retries vpn_run
  assert_success
  assert_equal "$(cat "$MOCK_ATTEMPT_FILE")" "2"
  assert_equal "$(cat "$OATHTOOL_COUNTER_FILE")" "2"
  refute_output --partial "$OPENCONNECT_PASSWORD"
  refute_output --partial "$OPENCONNECT_TOTP_SECRET"
  refute_output --partial "123451"
  refute_output --partial "123452"

  MOCK_STDIN_FILE="$MOCK_DIR/openconnect_stdin.1" assert_stdin_equals "secret123,123451"
  MOCK_STDIN_FILE="$MOCK_DIR/openconnect_stdin.2" assert_stdin_equals "secret123,123452"
}

@test "explicit MFA code takes precedence over TOTP on every comma attempt" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"
  export OPENCONNECT_MFA_FORMAT="comma"

  vpn_run >/dev/null
  assert_stdin_equals "secret123,654321"
  vpn_run >/dev/null
  assert_stdin_equals "secret123,654321"
  assert_equal "$(cat "$OATHTOOL_COUNTER_FILE")" "0"
}

@test "TOTP secret is regenerated on every run" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"

  # Must invoke vpn_run twice in the SAME shell so that OPENCONNECT_MFA_CODE
  # set/exported by the first call leaks into the second — that mirrors the
  # production retry-loop scenario. Using bats `run` would spawn a fresh
  # subshell and hide the bug.
  vpn_run >/dev/null
  first_stdin="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$first_stdin" "$(printf 'secret123\n123451')"

  vpn_run >/dev/null
  second_stdin="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$second_stdin" "$(printf 'secret123\n123452')"
}

@test "explicit MFA code takes precedence over TOTP secret" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="999999"
  export OPENCONNECT_TOTP_SECRET="JBSWY3DPEHPK3PXP"

  vpn_run >/dev/null
  first_stdin="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$first_stdin" "$(printf 'secret123\n999999')"

  # Reconnect must keep using the explicit code, not regenerate from the secret.
  vpn_run >/dev/null
  second_stdin="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$second_stdin" "$(printf 'secret123\n999999')"
}

# --- Cookie auth ---

@test "cookie mode uses --cookie-on-stdin when OPENCONNECT_COOKIE is set" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--cookie-on-stdin vpn.example.com"

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "webvpn=ABC123DEF456"
}

@test "cookie mode does not pass -u username flag" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  refute_output --partial "-u testuser"
}

@test "cookie mode with custom options passes them through" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"
  export OPENCONNECT_OPTIONS="--protocol=anyconnect --servercert pin-sha256:abc"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--protocol=anyconnect --servercert pin-sha256:abc --cookie-on-stdin vpn.example.com"
}

@test "cookie file mode reads cookie from JSON file" {
  cookie_file="$MOCK_DIR/cookie.json"
  echo '{"cookie": "webvpn=FROM_FILE_789", "host": "vpn.example.com"}' > "$cookie_file"
  export OPENCONNECT_COOKIE_FILE="$cookie_file"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "webvpn=FROM_FILE_789"
}

@test "cookie takes precedence over password auth" {
  export OPENCONNECT_COOKIE="webvpn=PRIORITY"
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."
  refute_output --partial "Password detected."
}

@test "comma MFA format preserves cookie and cookie-file authentication" {
  export OPENCONNECT_COOKIE="webvpn=PRIORITY"
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"
  export OPENCONNECT_MFA_FORMAT="comma"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."
  assert_equal "$(cat "$MOCK_ARGS_FILE")" "--cookie-on-stdin vpn.example.com"
  assert_stdin_equals "webvpn=PRIORITY"

  export OPENCONNECT_COOKIE_FILE="$MOCK_DIR/cookie.json"
  printf '%s\n' '{"cookie": "webvpn=FROM_FILE_789"}' > "$OPENCONNECT_COOKIE_FILE"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."
  assert_equal "$(cat "$MOCK_ARGS_FILE")" "--cookie-on-stdin vpn.example.com"
  assert_stdin_equals "webvpn=FROM_FILE_789"
}

@test "cookie file is ignored when file does not exist" {
  export OPENCONNECT_COOKIE_FILE="/nonexistent/cookie.json"
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Password detected."
}

# --- OPENCONNECT_OPTIONS ---

@test "custom options are passed through in password mode" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_OPTIONS="--authgroup MyGroup --protocol=gp"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--authgroup MyGroup --protocol=gp -u testuser --passwd-on-stdin vpn.example.com"
}

@test "custom options are passed through in interactive mode" {
  export OPENCONNECT_OPTIONS="--servercert pin-sha256:abc123"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--servercert pin-sha256:abc123 -u testuser vpn.example.com"
}

# --- VPN split ---

@test "VPN_SPLIT injects vpn-slice as script option" {
  export OPENCONNECT_PASSWORD="secret123"
  export VPN_SPLIT=1
  export VPN_ROUTES="10.0.0.0/8 172.16.0.0/12"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--script=vpn-slice 10.0.0.0/8 172.16.0.0/12 -u testuser --passwd-on-stdin vpn.example.com"
}

@test "VPN_SPLIT with custom options combines correctly" {
  export OPENCONNECT_PASSWORD="secret123"
  export VPN_SPLIT=1
  export VPN_ROUTES="10.0.0.0/8"
  export OPENCONNECT_OPTIONS="--protocol=anyconnect"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--protocol=anyconnect --script=vpn-slice 10.0.0.0/8 -u testuser --passwd-on-stdin vpn.example.com"
}

# --- Configurable ports and delay ---

@test "PROXY_PORT defaults to 8888" {
  run grep 'PROXY_PORT=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-8888'
}

@test "SOCKS_PORT defaults to 8889" {
  run grep 'SOCKS_PORT=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-8889'
}

@test "RECONNECT_DELAY defaults to 60" {
  run grep 'RECONNECT_DELAY=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-60'
}

@test "PROXY_PORT is used in tinyproxy sed and HEALTHCHECK" {
  count="$(grep -c 'PROXY_PORT' "$PROJECT_ROOT/build/entrypoint.sh")"
  [ "$count" -ge 2 ]
}

@test "SOCKS_PORT is used in microsocks startup" {
  run grep 'microsocks.*SOCKS_PORT' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
}

# --- Signal handling ---

@test "entrypoint.sh cleans up on every exit" {
  run grep 'trap cleanup EXIT' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
}

@test "entrypoint.sh converts TERM and INT into clean exits" {
  run grep "trap 'exit 0' TERM INT" "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
}

@test "cleanup function kills proxy PIDs" {
  run grep -A6 'cleanup()' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_output --partial 'TINYPROXY_PID'
  assert_output --partial 'MICROSOCKS_PID'
}

@test "cleanup preserves the entrypoint exit status" {
  run grep -A30 'cleanup()' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_output --partial 'status=$?'
  assert_output --partial 'exit "$status"'
}
