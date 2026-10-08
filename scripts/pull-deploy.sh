#!/usr/bin/env bash
# Slipcage pull deployment: only manually published GitHub releases from main.
set -euo pipefail
umask 077

REPO="soybeanfarmer/slipcage"
REMOTE="https://github.com/${REPO}.git"
ROOT="/var/lib/slipcage"
REPOSITORY="${ROOT}/source"
LAST="${ROOT}/deployed-sha"
LOCK="${ROOT}/pull-update.lock"
INVENTORY="/etc/slipcage/localhost.ini"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
mkdir -p "${ROOT}"
exec 9>"${LOCK}"
flock -n 9 || { echo "A deployment check is already running."; exit 0; }

api_get() {
  curl --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 30 \
    --header "Accept: application/vnd.github+json" \
    --header "X-GitHub-Api-Version: 2022-11-28" "$1"
}

# A published, non-draft, non-prerelease release is our explicit deployment approval.
# No release exists until the maintainer chooses to publish one.
release_json="$(api_get "https://api.github.com/repos/${REPO}/releases/latest")"
tag="$(printf '%s' "${release_json}" | python3 -c '
import json,sys
r=json.load(sys.stdin)
t=r.get("tag_name","")
if r.get("draft") or r.get("prerelease") or not isinstance(t,str):
    sys.exit(1)
print(t)
')"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][a-zA-Z0-9.-]+)?$ ]] || {
  echo "Refusing invalid release tag" >&2; exit 1;
}

if [[ ! -d "${REPOSITORY}/.git" ]]; then
  git clone --no-checkout "${REMOTE}" "${REPOSITORY}"
fi
[[ "$(git -C "${REPOSITORY}" remote get-url origin)" == "${REMOTE}" ]] || {
  echo "Unexpected Git remote" >&2; exit 1;
}
git -C "${REPOSITORY}" fetch --no-tags origin \
  "+refs/heads/main:refs/remotes/origin/main" \
  "refs/tags/${tag}:refs/tags/${tag}"

sha="$(git -C "${REPOSITORY}" rev-parse --verify "refs/tags/${tag}^{commit}")"
[[ "${sha}" =~ ^[a-f0-9]{40}$ ]] || exit 1
git -C "${REPOSITORY}" merge-base --is-ancestor "${sha}" refs/remotes/origin/main || {
  echo "Release is not on main; refusing deployment" >&2; exit 1;
}
[[ "$(cat "${LAST}" 2>/dev/null || true)" == "${sha}" ]] && {
  echo "Slipcage already deployed at ${sha}"; exit 0;
}

# Require a successful GitHub Actions CI check for this exact commit.
check_json="$(api_get "https://api.github.com/repos/${REPO}/commits/${sha}/check-runs?per_page=100")"
if ! printf '%s' "${check_json}" | python3 -c '
import json,sys
checks=json.load(sys.stdin).get("check_runs",[])
if not any(c.get("name")=="validate" and c.get("conclusion")=="success"
           and c.get("app",{}).get("slug")=="github-actions"
           for c in checks):
    sys.exit(1)
'; then
  echo "No successful GitHub Actions validation for ${sha}; deferring" >&2
  exit 0
fi

stage="$(mktemp -d /var/lib/slipcage/stage.XXXXXXXX)"
trap 'rm -rf -- "${stage}"' EXIT
git -C "${REPOSITORY}" archive "${sha}" | tar -x -C "${stage}"

# site.yml implements the deploy barrier: refuse unguarded upgrades, mark
# maintenance, wait for active jobs, install, verify, then release maintenance.
# On failure the last-deployed marker is NOT advanced.
ansible-playbook -i "${INVENTORY}" "${stage}/playbooks/site.yml"
printf '%s\n' "${sha}" > "${LAST}.tmp"
mv -f "${LAST}.tmp" "${LAST}"
echo "Slipcage deployed release ${tag} (${sha})"
