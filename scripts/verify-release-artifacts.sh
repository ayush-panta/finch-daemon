#!/usr/bin/env bash

#   Copyright The Finch Daemon Authors.

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# A script to verify artifacts from release automation.

set -o pipefail

cur_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
dinch_daemon_project_root="$(cd -- "$cur_dir"/.. && pwd)"
release_dir="${dinch_daemon_project_root}/release"

arch="amd64"

function usage {
    echo "Usage: $0 <release_tag>"
}

if [ $# -eq 0 ]; then
    echo "$0: Missing required argument"
    usage
    exit 1
fi

if [ ! -d "$release_dir" ]; then
    echo "$0: Release directory not found in $release_dir"
    exit 1
fi

release_tag=$1
# Strip 'v' from release tag.
release_version=${release_tag/v/} 

pushd "$release_dir" || exit 1
tarballs=("finch-daemon-${release_version}-linux-${arch}.tar.gz" "finch-daemon-${release_version}-linux-${arch}-static.tar.gz")
expected_contents=("finch-daemon" "THIRD_PARTY_LICENSES" "docker-credential-finch")
release_is_valid=true

for t in "${tarballs[@]}"; do
    # Verify each expected tarball was generated.
    if [[ ! -e $t ]]; then
        echo "$t: MISSING"
        release_is_valid=false
        continue
    fi

    # Verify the tarball's checksum is present and valid.
    if [[ ! -e "$t.sha256sum" ]] ; then
        echo "$t.sha256sum: MISSING"
        release_is_valid=false
        continue
    elif ( ! sha256sum -c "$t.sha256sum" &>/dev/null); then
        echo "$t.sha256sum: INVALID"
        release_is_valid=false
        continue
    fi

    # Read file names from tarball and strip './' if found.
    mapfile -t found_contents < <(tar -tf "$t" | sed -r 's/^.\///')

    content_matches=true

    # Verify the tarball only contains the expected contents.
    for file in "${found_contents[@]}"; do
        if [[ ! ${expected_contents[*]} =~ $file ]]; then
            echo "$file: UNEXPECTED"
            release_is_valid=false
            content_matches=false
        fi
    done

    # Verify the tarball is not missing any content.
    for file in "${expected_contents[@]}"; do
        if [[ ! ${found_contents[*]} =~ $file ]]; then
            echo "$file: MISSING"
            release_is_valid=false
            content_matches=false
        fi
    done

    if ${content_matches}; then
        echo "$t: OK"
    else
        echo "$t: INVALID"
    fi
done

if ( ! ${release_is_valid} ); then
    exit 1
fi

popd || exit 1
exit 0
