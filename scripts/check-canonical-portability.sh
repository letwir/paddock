#!/bin/sh
set -eu

output_dir=$(mktemp -d)
trap 'rm -rf "$output_dir"' EXIT HUP INT TERM
for target in windows/arm64 linux/arm64 android/arm64; do
  os=${target%/*}
  arch=${target#*/}
  printf '==> GOOS=%s GOARCH=%s CGO_ENABLED=0 go test -c ./internal/canonical\n' "$os" "$arch"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$output_dir/canonical-${os}-${arch}.test" ./internal/canonical
done
