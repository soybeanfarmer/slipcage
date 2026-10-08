#!/usr/bin/env bash
# Explicitly opt-in, encrypted off-server copy of latest verified snapshot.
set -Eeuo pipefail
umask 077

: "${RESTIC_REPOSITORY:?Configure root-only /etc/slipcage/offsite.env}"
: "${RESTIC_PASSWORD_FILE:?Set private RESTIC_PASSWORD_FILE}"

case "$RESTIC_REPOSITORY" in
  sftp:*|rest:https://*|s3:*|b2:*|azure:*|gs:*|rclone:*) ;;
  *) echo "Refusing local or unrecognized restic repository" >&2; exit 2 ;;
esac

[[ -f "$RESTIC_PASSWORD_FILE" && -r "$RESTIC_PASSWORD_FILE" ]] || {
  echo "Private restic password file absent or unreadable" >&2; exit 2;
}
[[ "$(stat -c %u "$RESTIC_PASSWORD_FILE")" == "0" ]] || {
  echo "Restic password file must be root-owned" >&2; exit 2;
}
perm="$(stat -c %a "$RESTIC_PASSWORD_FILE")"
(( (8#$perm & 077) == 0 )) || {
  echo "Restic password file must not be group/world readable" >&2; exit 2;
}

root="/var/backups/slipcage"
[[ -d "$root" && ! -L "$root" ]] || {
  echo "Local backup directory missing" >&2; exit 1;
}
exec 9>"/var/lib/slipcage/offsite.lock"
flock -n 9 || { echo "An offsite sync is already running"; exit 0; }

name="$(find "$root" -mindepth 1 -maxdepth 1 -type d \
  -name 'backup-????????T????????????Z' -printf '%f\n' | LC_ALL=C sort | tail -n1)"
[[ -n "$name" ]] || { echo "No completed local backups"; exit 1; }
snapshot="$root/$name"
now="$(date -u +%s)"
mtime="$(stat -c %Y "$snapshot")"
(( now >= mtime && now - mtime <= 129600 )) || {
  echo "Latest local backup older than 36 hours; refusing stale sync" >&2; exit 1;
}
/usr/local/sbin/slipcage-backup verify "$snapshot" >/dev/null

# Restic encrypts data before transfer. Credentials and repository setup
# are configured by the operator, never automatically by this script.
restic --no-cache backup --tag slipcage-verified "$snapshot"
echo "Encrypted offsite snapshot completed: $name"
