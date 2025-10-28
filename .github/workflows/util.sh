#!/usr/bin/env bash
set -e

if [ -n "${GITHUB_WORKSPACE}" ]; then
    # Inside a GitHub actions runner
    function group() {
        echo -e "::group::\e[${GROUP_COLOR};1m${1}\e[m"
    }
    function endgroup() {
        echo "::endgroup::"
    }
else
    # On another environment
    function group() {
        echo -e "\n\e[${GROUP_COLOR};1m${1}\e[m"
        echo -e "\e[${GROUP_COLOR};1m$(sed s/./=/g <<<"${1}")\e[m"
    }
    function endgroup() {
        echo -n
    }
fi
