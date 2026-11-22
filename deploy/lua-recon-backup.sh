#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
APP_DIR=/srv/canary/lua.micutu.com/app
DB=${APP_DIR}/data/recon.db
KEY=${APP_DIR}/data/session.key
LOG_DIR=${APP_DIR}/logs
BACKUP_DIR=/srv/backups/lua-recon
stamp="$(date -u +'%Y-%m-%dT%H%M%SZ')"
db_tmp="${BACKUP_DIR}/.recon-${stamp}.sqlite.tmp"
db_gz_tmp="${BACKUP_DIR}/.recon-${stamp}.sqlite.gz.tmp"
db_final="${BACKUP_DIR}/recon-${stamp}.sqlite.gz"
verify_db="${BACKUP_DIR}/.recon-${stamp}.verify.sqlite"

cleanup() {
  rm -f "${db_tmp}" "${db_gz_tmp}" "${verify_db}" \
    "${BACKUP_DIR}/.access-${stamp}.log.gz.tmp" \
    "${BACKUP_DIR}/.error-${stamp}.log.gz.tmp" \
    "${BACKUP_DIR}/.session-${stamp}.key.tmp"
}
trap cleanup EXIT

test -d "${BACKUP_DIR}"
sqlite3 "${DB}" ".timeout 10000" ".backup '${db_tmp}'"
test "$(sqlite3 "${db_tmp}" 'PRAGMA quick_check;')" = ok
gzip -n -9 -c "${db_tmp}" > "${db_gz_tmp}"
gzip -t "${db_gz_tmp}"
gzip -cd "${db_gz_tmp}" > "${verify_db}"
test "$(sqlite3 "${verify_db}" 'PRAGMA quick_check;')" = ok

for log in access error; do
  if [[ -f ${LOG_DIR}/${log}.log ]]; then
    gzip -n -6 -c "${LOG_DIR}/${log}.log" > \
      "${BACKUP_DIR}/.${log}-${stamp}.log.gz.tmp"
    gzip -t "${BACKUP_DIR}/.${log}-${stamp}.log.gz.tmp"
  fi
done

# Pair the private signing key with its database snapshot for recovery.
test "$(wc -c < "${KEY}")" -eq 32
install -m 0600 "${KEY}" "${BACKUP_DIR}/.session-${stamp}.key.tmp"
mv "${BACKUP_DIR}/.session-${stamp}.key.tmp" "${BACKUP_DIR}/session-${stamp}.key"
sha256sum "${BACKUP_DIR}/session-${stamp}.key" > "${BACKUP_DIR}/session-${stamp}.key.sha256"

mv "${db_gz_tmp}" "${db_final}"
sha256sum "${db_final}" > "${db_final}.sha256"
for log in access error; do
  tmp="${BACKUP_DIR}/.${log}-${stamp}.log.gz.tmp"
  if [[ -f ${tmp} ]]; then
    final="${BACKUP_DIR}/${log}-${stamp}.log.gz"
    mv "${tmp}" "${final}"
    sha256sum "${final}" > "${final}.sha256"
  fi
done

find "${BACKUP_DIR}" -xdev -type f \
  \( -name 'recon-*.sqlite.gz' -o -name 'recon-*.sqlite.gz.sha256' -o \
     -name 'access-*.log.gz' -o -name 'access-*.log.gz.sha256' -o \
     -name 'error-*.log.gz' -o -name 'error-*.log.gz.sha256' -o \
     -name 'session-*.key' -o -name 'session-*.key.sha256' \) \
  -mtime +14 -delete
cleanup
trap - EXIT
printf '%s backed up Lua recon DB and logs\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
