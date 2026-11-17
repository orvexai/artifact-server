#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ "${1:-}" == "--self-test" ]]; then
  python3 -B "$root/deploy/orvex/check-render.py" --self-test
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo "usage: deploy/orvex/check.sh [--self-test]" >&2
  exit 2
fi
for env in production rehearsal; do
  kustomize build "$root/deploy/orvex/$env" | python3 -B "$root/deploy/orvex/check-render.py" "$env"
done
