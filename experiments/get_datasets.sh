#!/usr/bin/env bash
# Clone the three public, deliberately misconfigured AWS datasets at the commits used in the report.
set -euo pipefail
DIR="${1:-../datasets}"
mkdir -p "$DIR" && cd "$DIR"
clone() { [ -d "$1" ] || git clone -q https://github.com/$2 "$1"; git -C "$1" checkout -q "$3"; echo "$1 @ $3"; }
clone terragoat bridgecrewio/terragoat      729f8da
clone sadcloud  nccgroup/sadcloud           f538652
clone cloudgoat RhinoSecurityLabs/cloudgoat 8b0895b
