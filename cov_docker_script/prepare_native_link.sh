#!/bin/bash
set -euo pipefail

mkdir -p "$HOME/usr/lib" "$HOME/usr/dummies"

for runtime in libgcrypt.so.20 libgpg-error.so.0; do
    crypto_library=$(gcc -print-file-name="$runtime")
    if [[ ! -f "$crypto_library" ]]; then
        echo "ERROR: Install the native $runtime runtime" >&2
        exit 1
    fi
    ln -sfn "$crypto_library" "$HOME/usr/lib/${runtime%%.so.*}.so"
done

echo "WARNING: creating link-only platform stubs for Coverity/native CI; the resulting binary is not runnable" >&2
for library in hal_moca hal_msomgmt cm_mgnt lmapi hal_ethsw telemetry_msgsender; do
    gcc -shared -x c /dev/null -o "$HOME/usr/dummies/lib$library.so"
done
