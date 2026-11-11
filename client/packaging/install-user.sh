#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX="${HOME}/.local"
mkdir -p "${PREFIX}/bin" "${PREFIX}/share/applications" "${HOME}/.config/fstec-client"
install -m 755 "${DIR}/fstec-client" "${PREFIX}/bin/fstec-client"
if [ ! -f "${HOME}/.config/fstec-client/fstec-client.conf" ]; then
  install -m 644 "${DIR}/fstec-client.conf" "${HOME}/.config/fstec-client/fstec-client.conf"
fi
sed "s|@EXEC@|${PREFIX}/bin/fstec-client|" "${DIR}/fstec-client.desktop" > "${PREFIX}/share/applications/fstec-client.desktop"
chmod 644 "${PREFIX}/share/applications/fstec-client.desktop"
printf 'Installed to %s\n' "${PREFIX}"
