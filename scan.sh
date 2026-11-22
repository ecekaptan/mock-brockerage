#!/usr/bin/env bash
# Run the same security gates locally before pushing. Requires: semgrep, gitleaks, trivy.
set -uo pipefail
fail=0

echo "== Semgrep (SAST) =="
semgrep scan --config p/python --config p/security-audit --severity ERROR --error || fail=1

echo "== Gitleaks (secrets) =="
gitleaks detect --source . --redact --verbose || fail=1

echo "== Trivy (deps) =="
trivy fs --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 . || fail=1

echo "== Trivy (config) =="
trivy config --severity HIGH,CRITICAL --exit-code 1 . || fail=1

[ "$fail" -eq 0 ] && echo "All gates passed" || { echo "One or more gates failed"; exit 1; }
