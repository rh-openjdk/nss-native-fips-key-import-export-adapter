#!/usr/bin/env bash
set -e

THIS_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
GROUP_COLOR=33
source "${THIS_DIR}/util.sh"

centos_version="${1}"
jdk_version="${2}"
if [ -z "${centos_version}" ] || [ -z "${jdk_version}" ]; then
    echo -e "Usage:\n    $0 <centos_version> <jdk_version>" 1>&2
    exit 1
fi

# Mock the Linux Kernel Cryptographic API files, so that the container sees as
# if the Kernel has been booted with fips=1. Of course this isn't a valid FIPS
# setup, but it allows testing the whole userspace portion of the FIPS mode
# software stack (of which we are particularly interested in NSS). NOTE: on
# Debian or Fedora we can do this at the /proc/sys/crypto level, but it looks
# like Ubuntu's Kernel removes the Cryptographic API (presumably to reintroduce
# it only for Ubuntu Pro), so we need to hook at the /proc/sys level (which is
# dirtier but it's working).
FAKE_PROC_SYS="/tmp/proc_sys"
group "Setup fake /proc/sys/crypto FIPS environment"
function cleanup() { rm -rf "${FAKE_PROC_SYS}"; }
trap cleanup EXIT
mkdir -p "${FAKE_PROC_SYS}/crypto"
tee "${FAKE_PROC_SYS}/crypto/fips_enabled" <<<"1"
tee "${FAKE_PROC_SYS}/crypto/fips_name" <<<"Linux Kernel Cryptographic API"
uname -r | tee "${FAKE_PROC_SYS}/crypto/fips_version"
endgroup

CONTAINER_SCRIPT=".github/workflows/containerized.sh"
group "Run ${CONTAINER_SCRIPT}"
podman run \
    "-v${FAKE_PROC_SYS}:/proc/sys:O" \
    "-v$(realpath "${THIS_DIR}/../.."):/opt/workspace:O" \
    "-eGITHUB_*" "-eNSS_*" --rm \
    "quay.io/centos/centos:stream${centos_version}" \
    bash "/opt/workspace/${CONTAINER_SCRIPT}" "${jdk_version}"
endgroup
