#!/usr/bin/env bash
# run-examples.sh - starts each long-lived program in examples/, waits until it
# answers HTTP, sends it SIGTERM and requires it to exit 0. It also calls
# api-auth with and without a token, and runs service-to-service against it, so
# the documented behaviour is checked as well as the start-up.
#
# Needs go, curl, openssl and python3. It needs no network beyond loopback.
set -euo pipefail

readonly readiness_attempts=100
readonly readiness_interval=0.1

work_dir="$(mktemp -d)"
declare -a pids=()

cleanup() {
  local pid
  for pid in "${pids[@]+"${pids[@]}"}"; do
    kill "${pid}" 2>/dev/null || true
  done
  rm -rf "${work_dir}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# start_example NAME PORT VAR=VALUE... builds examples/NAME and starts it on
# 127.0.0.1:PORT with the given environment. It records the process ID in
# example_pid and returns once the program answers HTTP.
start_example() {
  local name="$1" port="$2"
  shift 2

  go build -o "${work_dir}/${name}" "./examples/${name}"
  env "$@" "LISTEN_ADDR=127.0.0.1:${port}" "${work_dir}/${name}" 2>"${work_dir}/${name}.log" &
  example_pid=$!
  pids+=("${example_pid}")

  local attempt status
  for ((attempt = 0; attempt < readiness_attempts; attempt++)); do
    status="$(http_status "http://127.0.0.1:${port}/")"
    if [[ "${status}" != "000" ]]; then
      return 0
    fi
    if ! kill -0 "${example_pid}" 2>/dev/null; then
      cat "${work_dir}/${name}.log" >&2
      fail "${name} exited before it was ready"
    fi
    sleep "${readiness_interval}"
  done
  cat "${work_dir}/${name}.log" >&2
  fail "${name} was not ready on port ${port}"
}

# stop_example NAME PID sends SIGTERM and requires exit status 0.
stop_example() {
  local name="$1" pid="$2" status=0
  kill -TERM "${pid}"
  wait "${pid}" || status=$?
  if [[ "${status}" -ne 0 ]]; then
    cat "${work_dir}/${name}.log" >&2
    fail "${name} exited with status ${status} after SIGTERM"
  fi
  echo "ok: ${name} started, answered HTTP and exited 0 on SIGTERM"
}

# http_status URL [curl args...] prints the response status, or 000 when
# nothing answers.
http_status() {
  local url="$1"
  shift
  curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 "$@" "${url}" || true
}

# expect_status WANT URL [curl args...] fails unless the response status is WANT.
expect_status() {
  local want="$1" url="$2" got
  shift 2
  got="$(http_status "${url}" "$@")"
  [[ "${got}" == "${want}" ]] || fail "GET ${url}: want status ${want}, got ${got}"
  echo "ok: GET ${url} -> ${got}"
}

smoke_token() {
  SMOKE_JWT_SECRET=example-secret SMOKE_JWT_AUDIENCE=api-auth python3 scripts/gen_smoke_token.py "$@"
}

run_api_auth() {
  local port=18180 base admin user
  base="http://127.0.0.1:${port}"
  start_example api-auth "${port}" HMAC_SECRET=example-secret
  local pid="${example_pid}"

  admin="$(smoke_token --group api-admins)"
  user="$(smoke_token)"

  expect_status 200 "${base}/admin" --header "Authorization: Bearer ${admin}"
  expect_status 403 "${base}/admin" --header "Authorization: Bearer ${user}"
  expect_status 401 "${base}/whoami"
  expect_status 401 "${base}/whoami" --header "Authorization: Bearer not-a-token"
  expect_status 401 "${base}/admin" --cookie "auth_token=${admin}"

  # service-to-service is a one-shot program, so it is run to completion
  # rather than started and stopped.
  go build -o "${work_dir}/service-to-service" ./examples/service-to-service
  smoke_token --group api-admins --write-token-file "${work_dir}/token.yaml" >/dev/null
  local body
  body="$(TARGET_URL="${base}/admin" IDENTITY_TOKEN_FILE="${work_dir}/token.yaml" "${work_dir}/service-to-service" 2>/dev/null)" ||
    fail "service-to-service with an identity failed"
  [[ "${body}" == *"welcome, admin"* ]] || fail "service-to-service: unexpected response: ${body}"
  echo "ok: service-to-service called api-auth as its identity"
  if TARGET_URL="${base}/admin" "${work_dir}/service-to-service" >/dev/null 2>&1; then
    fail "service-to-service without an identity was not refused"
  fi
  echo "ok: service-to-service without an identity was refused"

  stop_example api-auth "${pid}"
}

run_browser_session() {
  local port=18181 key
  key="$(openssl rand -hex 32)"
  start_example browser-session "${port}" \
    OIDC_ISSUER=http://127.0.0.1:1 OIDC_CLIENT_ID=example OIDC_CLIENT_SECRET=example-secret \
    "COOKIE_ENCRYPTION_KEY=${key}"
  local pid="${example_pid}"

  # Without a session the page redirects to login and the API refuses.
  expect_status 303 "http://127.0.0.1:${port}/"
  expect_status 401 "http://127.0.0.1:${port}/api/me"
  expect_status 401 "http://127.0.0.1:${port}/api/me" --cookie "bff_session=not-a-session"

  stop_example browser-session "${pid}"
}

run_oidc_auth() {
  local port=18182
  start_example oidc-auth "${port}"
  local pid="${example_pid}"

  expect_status 401 "http://127.0.0.1:${port}/secure"

  stop_example oidc-auth "${pid}"
}

run_api_auth
run_browser_session
run_oidc_auth
echo "all examples ok"
