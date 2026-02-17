#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

set -e

if [ $# -ne 4 ]; then
    echo "Usage: ${0} NAME_VER VERSION REMOTE_NAME DIST_FILE" 1>&2
    exit 1
fi
NAME_VER="${1}"
VERSION="${2}"
REMOTE_NAME="${3}"
DIST_FILE="${4}"

# Check and collect the required data
if [ -n "$(git status --porcelain)" ]; then
    echo "will not tag: the working tree must be clean" 1>&2
    exit 2
fi
gh_token="$(secret-tool lookup protocol https server github.com)"
if [ -z "${gh_token}" ]; then
    echo "could not get the GitHub token" 1>&2
    exit 3
fi
remote_url="$(git remote get-url "${REMOTE_NAME}")"
if [ -z "${remote_url}" ]; then
    echo "could not get the git remote url for ${REMOTE_NAME}" 1>&2
    exit 4
fi
owner="$(basename "$(dirname "${remote_url}")")"
repo="$(basename "${remote_url}" .git)"
prev_version="$(git describe --abbrev=0)"
body="
### All-Time Contributors

@franferrax, @martinuy, @fitzsim, @gnu-andrew

### Changelog

https://github.com/${owner}/${repo}/compare/${prev_version}...${VERSION}

### Notes

\`${DIST_FILE}\` is the official release source, \`*.zip\` and \`*.tar.gz\` files are empty on purpose, since GitHub doesn't allow deleting them.
"
COMMON_HEADERS=(
    -L -X POST -H "Authorization: Bearer ${gh_token}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
)
url="https://api.github.com/repos/${owner}/${repo}/releases"
data="$(python3 '-BIScimport json, sys
tag_name, name, body = sys.argv[1:]
print(json.dumps(dict(tag_name=tag_name, name=name, body=body.strip())))
' "${VERSION}" "${NAME_VER}" "${body}")"

# Tag and publish GitHub release
git tag -s "${VERSION}" -m "${NAME_VER}"
git push "${REMOTE_NAME}" tag "${VERSION}"
resp="$(curl "${COMMON_HEADERS[@]}" "${url}" --data "${data}")"
echo "${resp}"

# Upload dist file
upload_url="$(python3 '-BIScimport json, sys
print(json.load(sys.stdin)["upload_url"].split("{")[0])' <<<"${resp}")"
curl "${COMMON_HEADERS[@]}" -H "Content-Type: application/octet-stream" \
    "${upload_url}?name=${DIST_FILE}" --data-binary "@${DIST_FILE}"
