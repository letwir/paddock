#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

fail() { printf 'run_poc_harness: %s\n' "$1" >&2; exit 1; }
: "${PADDOCK_DB_URL:?PADDOCK_DB_URL must be injected by operator; value will not be printed}"
command -v go >/dev/null 2>&1 || fail 'go executable not found'
command -v psql >/dev/null 2>&1 || fail 'psql executable not found'
command -v curl >/dev/null 2>&1 || fail 'curl executable not found'

# Read-only identity guard; output includes no connection URL or credential.
scripts/init_test_db.sh --check

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/paddock-harness.XXXXXX")
pids=()
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for _ in $(seq 1 50); do
    local alive=0
    for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    [[ "$alive" -eq 0 ]] && break
    sleep 0.1
  done
  for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf -- "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

go build -o "$tmp_dir/coordinator" ./cmd/coordinator
go build -o "$tmp_dir/worker-sim" ./cmd/worker-sim

for id in coordinator-a coordinator-b; do
  "$tmp_dir/coordinator" -id "$id" -listen 127.0.0.1:0 >"$tmp_dir/$id.log" 2>&1 &
  pids+=("$!")
done

wait_for_url() {
  local log_file=$1
  for _ in $(seq 1 100); do
    if grep -q 'coordinator=[^ ]* listen=' "$log_file"; then
      result_url=$(sed -n 's/^.*coordinator=[^ ]* listen=\([^ ]*\) database=.*/http:\/\/\1/p' "$log_file")
      [[ -n "$result_url" ]] || fail 'could not parse coordinator address'
      return 0
    fi
    sleep 0.1
  done
  cat "$log_file" >&2
  fail 'timed out waiting for coordinator listen address'
}
wait_for_url "$tmp_dir/coordinator-a.log"
url_a=$result_url
wait_for_url "$tmp_dir/coordinator-b.log"
url_b=$result_url
[[ "$url_a" == http://127.0.0.1:* || "$url_a" == http://\[::1\]:* ]] || fail 'coordinator A did not bind to loopback'
[[ "$url_b" == http://127.0.0.1:* || "$url_b" == http://\[::1\]:* ]] || fail 'coordinator B did not bind to loopback'

worker_coordinators=("$url_a" "$url_b")
worker_ids=(worker-a worker-b)
for index in 0 1; do
  id=${worker_ids[$index]}
  coordinator_url=${worker_coordinators[$index]}
  "$tmp_dir/worker-sim" -id "$id" -coordinator "$coordinator_url" -interval 250ms >"$tmp_dir/$id.log" 2>&1 &
  pids+=("$!")
done

for _ in $(seq 1 50); do
  if curl -fsS "$url_a/healthz" >/dev/null && curl -fsS "$url_b/healthz" >/dev/null; then break; fi
  sleep 0.1
done
for url in "$url_a" "$url_b"; do curl -fsS "$url/healthz" >/dev/null || fail 'coordinator health check failed'; done
for _ in $(seq 1 50); do
  if grep -q 'received=0' "$tmp_dir/worker-a.log" && grep -q 'received=0' "$tmp_dir/worker-b.log"; then break; fi
  sleep 0.1
done
grep -q 'received=0' "$tmp_dir/worker-a.log" || fail 'worker A did not complete a pull'
grep -q 'received=0' "$tmp_dir/worker-b.log" || fail 'worker B did not complete a pull'
grep -q 'coordinator=coordinator-a received=0' "$tmp_dir/worker-a.log" || fail 'worker A did not use coordinator A'
grep -q 'coordinator=coordinator-b received=0' "$tmp_dir/worker-b.log" || fail 'worker B did not use coordinator B'
printf 'Harness PASS coordinators=2 workers=2 database=paddock_test scheduler=stub jobs_executed=0\n'
exit 0
