#!/usr/bin/env bash
set -e

THIS_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
GROUP_COLOR=36
source "${THIS_DIR}/util.sh"

group "Set the FIPS crypto policy"
update-crypto-policies --set FIPS
endgroup

group "Install build dependencies"
dnf install -y git make gcc nss-devel
endgroup

group "Build"
cd "${THIS_DIR}/../.."
make release
endgroup

jdk_ver="${1}"
group "Download Adoptium Temurin JDK ${jdk_ver}"
JAVA_HOME="/opt/jdk${jdk_ver}"
os="$(uname -s | tr "[:upper:]" "[:lower:]")"
arch="$(uname -m | sed "s/x86_64/x64/;s/x86/x32/")"
api_url="https://api.adoptium.net/v3/assets/latest/${jdk_ver}/hotspot"
api_url="${api_url}?image_type=jdk&os=${os}&architecture=${arch}"
echo "Adoptium API URL: ${api_url}"
api_parser_py='-BISc
import json, sys
print(json.load(sys.stdin)[0]["binary"]["package"]["link"])'
jdk_url="$(curl -qsSL "${api_url}" | python3 "${api_parser_py}")"
echo "Adoptium JDK URL: ${jdk_url}"
mkdir -p "${JAVA_HOME}"
curl -qsSL "${jdk_url}" | tar --strip-components=1 -xzC "${JAVA_HOME}"
endgroup

group "Run the tests"
failed=false
"${JAVA_HOME}/bin/java" -version
make test "JAVA=${JAVA_HOME}/bin/java" || failed=true
endgroup

if $failed; then
    group "Rerun the tests with full debugging output"
    NSS_ADAPTER_DEBUG=color make test "JAVA=${JAVA_HOME}/bin/java"
    endgroup
fi
