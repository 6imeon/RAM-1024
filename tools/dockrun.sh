#!/bin/sh
# Run an analysis command in a cached Debian image that has CaDiCaL and z3
# (built once as ramci-sat:<hash>), with the repo mounted read-write so
# results land in results/ (or $RAM_RESULTS). Budget variables are passed in.
#     sh tools/dockrun.sh python3 analysis/trail_bounds.py 300 4
set -eu
cd "$(dirname "$0")/.."
SETUP='apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 python3-z3 cadical >/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/*'
TAG="ramci-sat:$(printf '%s' "$SETUP" | cksum | cut -d' ' -f1)"
if ! docker image inspect "$TAG" >/dev/null 2>&1; then
    tmp="ramci-setup-sat-$$"
    docker run --label ramci=1 --name "$tmp" debian:bookworm-slim sh -c "$SETUP"
    docker commit "$tmp" "$TAG" >/dev/null
    docker rm "$tmp" >/dev/null
fi
exec docker run --rm --init --label ramci=1 --label "ramsuite=${RAMSUITE:-none}" \
    -e RAM_DEADLINE="${RAM_DEADLINE:-}" -e RAM_RESULTS="${RAM_RESULTS:-}" \
    -e RAM_THREADS="${RAM_THREADS:-}" -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$PWD:/src" -w /src "$TAG" "$@"
