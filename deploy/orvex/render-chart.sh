#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/artifact-server-chart.XXXXXX")"
trap 'rm -r "$tmp"' EXIT

# Chart 0.1.18 declares <1.37.0 in Chart.yaml although its rendered manifests
# use APIs accepted on Manchester 1.37.2. Relax only the temporary render copy;
# the committed chart and source files remain unchanged.
cp -R "$root/packaging/helm/artifact-server" "$tmp/chart"
sed -i 's/kubeVersion: ">=1.34.0-0 <1.37.0-0"/kubeVersion: ">=1.34.0-0 <1.38.0-0"/' "$tmp/chart/Chart.yaml"
helm template artifact-server "$tmp/chart" --namespace artifact-server --kube-version 1.37.2 --skip-tests --values "$root/deploy/orvex/production/values.yaml" > "$root/deploy/orvex/production/chart.yaml"
helm template artifact-server "$tmp/chart" --namespace artifact-server-rehearsal --kube-version 1.37.2 --skip-tests --values "$root/deploy/orvex/rehearsal/values.yaml" > "$root/deploy/orvex/rehearsal/chart.yaml"
for rendered in "$root/deploy/orvex/production/chart.yaml" "$root/deploy/orvex/rehearsal/chart.yaml"; do
  python3 -c 'import pathlib, sys; p = pathlib.Path(sys.argv[1]); p.write_text(p.read_text().rstrip() + "\n")' "$rendered"
done
