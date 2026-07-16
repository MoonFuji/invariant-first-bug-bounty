#!/usr/bin/env bash
# recon-sweep.sh — model-gated sink + secret + CI/CD coverage over a cloned repo.
#
# Purpose: run broad coverage only after candidate.json records a concrete security
# model and invariant. It is a TRIAGE pass, not a verifier. Every hit must attach to
# the selected invariant and be traced to a reachable effect.
#
# Usage:   recon-sweep.sh --candidate candidate.json <repo-dir> [output-dir]
# Example: recon-sweep.sh --candidate ./hunt/candidate.json ./klaw_hunt /tmp/klaw-recon
#
# Degrades gracefully: uses ripgrep if present (falls back to grep -r), and runs
# semgrep/gitleaks/trufflehog only if they're installed. Read-only; writes only to
# the output dir. Installs nothing.

set -uo pipefail

usage() {
  echo "usage: recon-sweep.sh --candidate candidate.json <repo-dir> [output-dir]" >&2
}

if [ "$#" -lt 3 ] || [ "$1" != "--candidate" ]; then
  usage
  exit 2
fi

CANDIDATE="$2"
REPO="$3"
OUT="${4:-./recon-$(basename "$REPO")}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="$SCRIPT_DIR/validate-candidate.py"

if [ ! -d "$REPO" ]; then
  echo "[error] repository directory not found: $REPO" >&2
  exit 2
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "[error] python 3 is required to validate candidate state" >&2
  exit 2
fi

if ! "$PYTHON" "$VALIDATOR" --stage model "$CANDIDATE"; then
  echo "[error] candidate is not model-ready; fix the listed fields before broad recon" >&2
  exit 2
fi

mkdir -p "$OUT"

if command -v rg >/dev/null 2>&1; then
  GREP() { rg -n --no-heading -S "$@" "$REPO" 2>/dev/null; }
else
  echo "[i] ripgrep not found; falling back to grep -r (slower)" >&2
  GREP() { local pat="$1"; shift; grep -rnIE "$@" "$pat" "$REPO" 2>/dev/null; }
fi

sweep() { # sweep <label> <regex>
  local label="$1" pat="$2" f="$OUT/${1}.txt"
  GREP "$pat" > "$f"
  local n; n=$(wc -l < "$f" | tr -d ' ')
  printf '  %-28s %s hits -> %s\n' "$label" "$n" "$f"
}

echo "== model-gated coverage: $REPO -> $OUT =="
echo "   candidate: $CANDIDATE"

# --- Injection / command / code-exec ---
sweep sql-raw            'whereRaw|selectRaw|orderByRaw|DB::raw|\.raw\(|sequelize\.query|knex\.raw|cursor\.execute|\.extra\(|RawSQL|fmt\.Sprintf.*(Query|Exec)'
sweep cmd-exec           'shell_exec|passthru|proc_open|popen|child_process|execSync|os\.system|subprocess\.|shell=True|exec\.Command'
sweep code-eval          '\beval\(|new Function\(|render_template_string|Template\(|vm\.runInNewContext|SpEL|#\{'

# --- Deserialization ---
sweep deserialize        'unserialize\(|pickle\.load|yaml\.load\(|yaml\.unsafe_load|Marshal\.load|ObjectInputStream|readObject|BinaryFormatter|node-serialize|allow_pickle=True'

# --- SSRF / URL fetch ---
sweep ssrf-fetch         'axios\.(get|post)|fetch\(|requests\.(get|post)|urllib|httpx|http\.Get|file_get_contents|curl_exec|HttpClient'

# --- Path traversal / file write / archive ---
sweep path-archive       'os\.path\.join|filepath\.Join|with_file_name|extractall|sendFile|readFile|fopen|include\(|require\(|php://|phar://|\.\./'

# --- XXE ---
sweep xxe                'simplexml_load|loadXML|DocumentBuilder|XMLInputFactory|etree|lxml|XmlDocument|SAXParser'

# --- AuthZ smells (read these by hand — high EV) ---
sweep authz-lookup       'findById|findByUsername|findOne\(|objects\.get\(|getUsersInfo|\.findByX|where.*id.*=.*req|params\.id'
sweep tenant-from-body   'tenantId|orgId|accountId|workspaceId|teamId' # check: from principal or from request body?

# --- AuthN / tokens / crypto ---
sweep weak-random        'Math\.random|mt_rand|\buniqid\(|\brand\(|random\.(random|choice|randint)|math/rand'
sweep jwt                'jwt\.verify|alg.*none|algorithms|decode\(.*verify=False'
sweep crypto-compare     '\b(==|equals|bytes\.Equal)\b.*(token|secret|hmac|signature|password)|ECB|MD5|SHA1'

# --- XSS / client sinks ---
sweep xss-sinks          'innerHTML|dangerouslySetInnerHTML|document\.write|v-html|mark_safe|\|safe|html_safe|bypassSecurityTrust|\{!!'
sweep prototype-pollution '_\.merge|_\.defaultsDeep|defaultsDeep|deepmerge|Object\.assign|__proto__|constructor\]\[|set\(.*path'
sweep postmessage        "addEventListener\\(['\"]message"

# --- Mass assignment / redirect ---
sweep mass-assign        'request->all\(\)|fill\(\$request|new .*\(req\.body\)|\.create\(req\.|ModelForm'
sweep open-redirect      'redirect\(.*req|Location: .*\$|RedirectResponse\(|res\.redirect'

echo
echo "== CI/CD workflows (pull_request_target / script injection / broad perms) =="
if [ -d "$REPO/.github/workflows" ]; then
  GREP 'pull_request_target|\$\{\{\s*github\.event|permissions:|uses:.*@(main|master)' > "$OUT/cicd.txt"
  printf '  cicd -> %s (%s lines)\n' "$OUT/cicd.txt" "$(wc -l < "$OUT/cicd.txt" | tr -d ' ')"
else
  echo "  (no .github/workflows)"
fi

echo
echo "== secrets / known-CVE deps (optional tools) =="
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$REPO" --no-banner -r "$OUT/gitleaks.json" >/dev/null 2>&1 \
    && echo "  gitleaks -> $OUT/gitleaks.json" || echo "  gitleaks ran (see $OUT/gitleaks.json)"
else
  echo "  [skip] gitleaks not installed (scans committed secrets + history)"
fi
if command -v trufflehog >/dev/null 2>&1; then
  trufflehog filesystem "$REPO" --json > "$OUT/trufflehog.json" 2>/dev/null \
    && echo "  trufflehog -> $OUT/trufflehog.json"
else
  echo "  [skip] trufflehog not installed (verified-secret scanning + git history)"
fi
if command -v semgrep >/dev/null 2>&1; then
  echo "  [i] semgrep present — run targeted variant analysis with your own rule:"
  echo "      semgrep --config auto $REPO   (or --config <your-rule.yaml>)"
else
  echo "  [skip] semgrep not installed (deep taint + variant analysis)"
fi
if command -v osv-scanner >/dev/null 2>&1; then
  osv-scanner --recursive "$REPO" > "$OUT/osv.txt" 2>/dev/null \
    && echo "  osv-scanner -> $OUT/osv.txt (known-CVE deps in scope)"
fi

echo
echo "== next steps =="
echo "  1. Triage only hits relevant to candidate.json's selected invariant."
echo "  2. Trace attacker input through the authoritative enforcement point to an observable effect."
echo "  3. After one confirmed causal pattern, encode it for semantic variant analysis."
echo "  4. Update candidate.json; report drafting remains blocked until --stage report passes."
