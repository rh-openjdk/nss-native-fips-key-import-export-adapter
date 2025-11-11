#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

set -e

#
# Globals
#
THIS_FILE="$(realpath "${BASH_SOURCE[0]}")"
THIS_DIR="$(dirname "${THIS_FILE}")"
WORKSPACE="$(dirname "${THIS_DIR}")"
MOUNTED_WORKSPACE="/opt/workspace"
CENTOS_VERSION=""
JDK_VERSION=""

#
# Logging helpers
#
LOGGING_COLOR=33
if [ -n "${GITHUB_WORKSPACE}" ]; then
    # Inside a GitHub actions runner, create collapsible groups
    GROUP_START="::group::"
    GROUP_END="::endgroup::"
else
    GROUP_START=""
    GROUP_END=""
fi

function group() {
    local ts
    SECONDS=0
    ts="$(date -u +"%Y-%m-%d %H:%M:%S.%N UTC")"
    echo -e "${GROUP_START}\e[${LOGGING_COLOR};1m[${ts}] ${1}\e[m"
}

function endgroup() {
    echo -e "\e[${LOGGING_COLOR};1m(elapsed time: ${SECONDS} seconds)\e[m"
    echo -e "${GROUP_END}"
}

#
# Entry point
#
function main() {
    CENTOS_VERSION="${1}"
    JDK_VERSION="${2}"
    if [ -z "${CENTOS_VERSION}" ] || [ -z "${JDK_VERSION}" ]; then
        exit 1
    fi

    cd "${WORKSPACE}"
    if [ -d "${MOUNTED_WORKSPACE}" ]; then
        # Inside the container, change the logging color
        LOGGING_COLOR=36
        containerized_run
    else
        container_build
    fi
}

#
# Container building and running
#
function container_build() {
    local image_name this_file_rel fake_proc_sys_mount workspace_mount

    image_name="c${CENTOS_VERSION}s"
    this_file_rel="$(basename "${THIS_DIR}")/$(basename "${THIS_FILE}")"
    group "Prepare ${image_name} container image with build dependencies"
    podman build - -t "${image_name}" <<-EOF
		FROM quay.io/centos/centos:stream${CENTOS_VERSION}
		RUN update-crypto-policies --set FIPS
		RUN dnf install -y make gcc nss-devel
		ENTRYPOINT ["bash", "${MOUNTED_WORKSPACE}/${this_file_rel}"]
	EOF
    endgroup

    # See fake_proc_sys/crypto/README
    fake_proc_sys_mount="-v${THIS_DIR}/fake_proc_sys:/proc/sys:O"
    workspace_mount="-v${WORKSPACE}:${MOUNTED_WORKSPACE}:O"
    podman run "${fake_proc_sys_mount}" "${workspace_mount}" \
        "-eGITHUB_*" "-eNSS_*" --rm "${image_name}" \
        "${CENTOS_VERSION}" "${JDK_VERSION}"
}

#
# Execution inside the container
#
function download_temurin_jdk() {
    local api_url jdk_url

    api_url="https://api.adoptium.net/v3/assets/latest/${JDK_VERSION}"
    api_url="${api_url}/hotspot?image_type=jdk"
    api_url="${api_url}&os=$(uname -s | tr "[:upper:]" "[:lower:]")"
    api_url="${api_url}&architecture=$(uname -m)"

    echo "Adoptium API URL: ${api_url}"
    jdk_url="$(curl -qsSL "${api_url}" | python3 -BISc "$(
        cat <<-EOF
			import json, sys
			print(json.load(sys.stdin)[0]["binary"]["package"]["link"])
		EOF
    )")"

    echo "Adoptium JDK URL: ${jdk_url}"
    export JAVA_HOME="/opt/jdk${JDK_VERSION}"
    mkdir -p "${JAVA_HOME}"
    curl -qsSL "${jdk_url}" | tar --strip-components=1 -xzC "${JAVA_HOME}"
    "${JAVA_HOME}/bin/java" -version
}

function containerized_run() {
    local failed

    group "Build"
    make release
    endgroup

    group "Download Adoptium Temurin JDK ${JDK_VERSION}"
    download_temurin_jdk
    endgroup

    group "Run the tests"
    failed=false
    make test-exec || failed=true
    endgroup

    if $failed; then
        group "Rerun the tests with full debugging output"
        NSS_ADAPTER_DEBUG=color make test-exec
        endgroup
    fi
}

main "$@"
