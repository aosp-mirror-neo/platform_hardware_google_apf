#!/bin/bash
set -e
set -u

# Script to quickly build a static aarch64 version of the tool for quick 'adb push' installation.
#
# May need some of the following:
#   sudo apt-get update
#   sudo apt-get install libnl-3-dev libnl-genl-3-dev build-essential crossbuild-essential-arm64

declare -r NL='../../../../external/libnl'
declare -r NLIB="${NL}/lib"

for vendor in brcm qcom; do
  gcc -Wall -Werror -D__unused= -I/usr/include/libnl3 "${vendor}_apf_tool.c" -o "${vendor}_apf_tool.exe" -lnl-3 -lnl-genl-3
  aarch64-linux-gnu-gcc -static \
    -D__unused='__attribute__((unused))' \
    -D_GNU_SOURCE \
    -I "${NL}/include" \
    "${NLIB}/addr.c" \
    "${NLIB}/attr.c" \
    "${NLIB}/cache.c" \
    "${NLIB}/cache_mngt.c" \
    "${NLIB}/data.c" \
    "${NLIB}/error.c" \
    "${NLIB}/genl/ctrl.c" \
    "${NLIB}/genl/family.c" \
    "${NLIB}/genl/genl.c" \
    "${NLIB}/genl/mngt.c" \
    "${NLIB}/handlers.c" \
    "${NLIB}/hash.c" \
    "${NLIB}/hashtable.c" \
    "${NLIB}/mpls.c" \
    "${NLIB}/msg.c" \
    "${NLIB}/nl.c" \
    "${NLIB}/object.c" \
    "${NLIB}/socket.c" \
    "${NLIB}/utils.c" \
    "${vendor}_apf_tool.c" -o "${vendor}_apf_tool"
done

# /usr/lib/gcc-cross/aarch64-linux-gnu/14/../../../../aarch64-linux-gnu/bin/ld: /tmp/ccYCWTVb.o: in function `nl_addr_info':
# addr.c:(.text+0x1410): warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
# /usr/lib/gcc-cross/aarch64-linux-gnu/14/../../../../aarch64-linux-gnu/bin/ld: /tmp/ccNB9nWJ.o: in function `nl_getprotobynumber':
# utils.c:(.text+0x358): warning: Using 'getprotobynumber' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
# /usr/lib/gcc-cross/aarch64-linux-gnu/14/../../../../aarch64-linux-gnu/bin/ld: /tmp/ccNB9nWJ.o: in function `nl_getprotobyname':
# utils.c:(.text+0x2e8): warning: Using 'getprotobyname' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking

echo 'You may ignore above warnings about using get{addrinfo,protobynumber,protobyname} in statically linked applications.'
