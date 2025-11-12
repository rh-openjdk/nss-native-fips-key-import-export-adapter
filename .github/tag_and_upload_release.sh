#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

set -e

if [ $# -ne 4 ]; then
    echo "Usage: ${0} NAME VERSION REMOTE_NAME DIST_FILE" 1>&2
    exit 1
fi
NAME="${1}"
VERSION="${2}"
REMOTE_NAME="${3}"
DIST_FILE="${4}"

# Tag the current version and push the tag
if [ "$(git status --porcelain | wc -l)" -ne 0 ]; then
    echo "will not tag: the working tree must be clean" 1>&2
    exit 2
fi
release_name="${NAME} v${VERSION}"
git tag -s "${VERSION}" -m "${release_name}"
git push "${REMOTE_NAME}" tag "${VERSION}"

# Obtain GitHub data required to use the REST API
gh_token="$(echo -e 'protocol=https\nhost=github.com' |
    /usr/libexec/git-core/git-credential-libsecret get |
    sed -n s/password=//p)"
if [ -z "${gh_token}" ]; then
    echo "could not get the GitHub token" 1>&2
    exit 3
fi

remote_url="$(git remote get-url "${REMOTE_NAME}")"
if [ -z "${remote_url}" ]; then
    echo "could not get the git remote url for ${REMOTE_NAME}" 1>&2
    exit 4
fi
owner="$(echo "${remote_url%*.git}" | tr / '\n' | tail -2 | head -1)"
repo="$(echo "${remote_url%*.git}" | tr / '\n' | tail -1)"

# Publish GitHub release
COMMON_HEADERS=(
    -L -X POST -H "Authorization: Bearer ${gh_token}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
)
body="Note: \`${DIST_FILE}\` is the official release source, \`*.zip\`"
body="${body} and \`*.tar.gz\` files are empty on purpose, since GitHub"
body="${body} doesn't allow deleting them."
data="$(
    cat <<-EOF
	{
	  "tag_name": "${VERSION}",
	  "name": "${release_name}",
	  "body": "${body}"
	}
	EOF
)"
url="https://api.github.com/repos/${owner}/${repo}/releases"
resp="$(curl "${COMMON_HEADERS[@]}" "${url}" --data "${data}")"
echo "${resp}"

# Upload dist file
upload_url="$(python3 '-BIScimport json, sys
print(json.load(sys.stdin)["upload_url"].split("{")[0])' <<<"${resp}")"
curl "${COMMON_HEADERS[@]}" -H "Content-Type: application/octet-stream" \
    "${upload_url}?name=${DIST_FILE}" --data-binary "@${DIST_FILE}"
