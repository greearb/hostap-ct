#!/bin/sh
# Run independently of a radio or a running supplicant/hostapd process.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

for debug_file in no yes; do
	flags=
	if [ "$debug_file" = yes ]; then
		flags=-DCONFIG_DEBUG_FILE
	fi
	${CC:-cc} -Wall -Wextra -Werror -Wno-unused-parameter \
		-ffunction-sections -fdata-sections $flags \
		-I"$root/src" -I"$root/src/utils" \
		"$root/tests/test-key-events.c" \
		"$root/src/utils/wpa_debug.c" \
		"$root/src/utils/common.c" \
		"$root/src/utils/os_unix.c" \
		-Wl,--gc-sections -o "$tmp/test-key-events"
	"$tmp/test-key-events"
	if [ "$debug_file" = yes ]; then
		"$tmp/test-key-events" "$tmp/debug.log"
	fi
done
