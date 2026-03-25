#!/bin/bash -eu
#
# Copyright 2018 The Outline Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Shadowbox Integration Test
#
# This test verifies that a client can access a target website via a shadowbox node.
# Sets up a target in the LAN to validate that it cannot be accessed through shadowbox.
#
# Architecture:
#
# +--------+     +-----------+
# | Client | --> | Shadowbox | -->  Internet
# +--------+     +-----------+
#                      |           +--------+
#                      ----//----> | Target |
#                                  +--------+
#
# Each node runs on a different Docker container.

set -x

OUTPUT_DIR="${OUTPUT_DIR:-$(mktemp -d)}"
readonly OUTPUT_DIR

# Set DOCKER=podman to use Podman instead of Docker.
readonly DOCKER="${DOCKER:-docker}"

# TODO(fortuna): Make it possible to run multiple tests in parallel by adding a
# run id to the container names.
readonly NAMESPACE='integrationtest'
readonly TARGET_CONTAINER="${NAMESPACE}_target"
readonly TARGET_IMAGE="${TARGET_CONTAINER}"
readonly SHADOWBOX_IMAGE="${1?Must pass image name in the command line}"
readonly SHADOWBOX_CONTAINER="${NAMESPACE}_shadowbox"
readonly CLIENT_CONTAINER="${NAMESPACE}_client"
readonly CLIENT_IMAGE="${CLIENT_CONTAINER}"

readonly NET_OPEN="${NAMESPACE}_open"
readonly NET_BLOCKED="${NAMESPACE}_blocked"


readonly INTERNET_TARGET_URL="http://www.gstatic.com/generate_204"
echo "Test output at ${OUTPUT_DIR}"
# Set DEBUG=1 to not kill the stack when the test is finished so you can query
# the containers.
declare -ir DEBUG=${DEBUG:-0}

# Waits for the input URL to return success.
function wait_for_resource() {
  local -r URL="$1"
  until curl --silent --insecure "${URL}" > /dev/null; do sleep 1; done
}

function util_jq() {
  "${DOCKER}" run --rm -i ghcr.io/jqlang/jq "$@"
}

# Takes the JSON from a /access-keys POST request and returns the appropriate
# ss-local arguments to connect to that user/instance.
function ss_arguments_for_user() {
  local SS_INSTANCE_CIPHER SS_INSTANCE_PASSWORD
  SS_INSTANCE_CIPHER="$(echo "$1" | util_jq -r .method)"
  SS_INSTANCE_PASSWORD="$(echo "$1" | util_jq -r .password)"
  local -i SS_INSTANCE_PORT
  SS_INSTANCE_PORT=$(echo "$1" | util_jq .port)
  echo -cipher "${SS_INSTANCE_CIPHER}" -password "${SS_INSTANCE_PASSWORD}" -c "shadowbox:${SS_INSTANCE_PORT}"
}

# Runs curl on the client container.
function client_curl() {
  "${DOCKER}" exec "${CLIENT_CONTAINER}" curl --silent --show-error --connect-timeout 5 --retry 5 "$@"
}

function fail() {
  echo FAILED: "$@"
  exit 1
}

function setup() {
  remove_containers

  "${DOCKER}" network create -d bridge "${NET_OPEN}"
  "${DOCKER}" network create -d bridge --internal "${NET_BLOCKED}"

  # Target service.
  "${DOCKER}" build --force-rm -t "${TARGET_IMAGE}" "$(dirname "$0")/target"
  "${DOCKER}" run -d --rm -p "10080:80" --network="${NET_OPEN}" --network-alias="target" --name="${TARGET_CONTAINER}" "${TARGET_IMAGE}"

  # Shadowsocks service.
  # Start on NET_OPEN first so that -p host port binding works on macOS Docker Desktop
  # (Docker Desktop does not publish ports when the initial network is --internal).
  # Then connect to NET_BLOCKED so the security isolation tests still pass.
  declare -ar shadowbox_flags=(
    -d
    --rm
    --network="${NET_OPEN}"
    --network-alias="shadowbox"
    -p "20443:443"
    -e "SB_API_PORT=443"
    -e "SB_API_PREFIX=${SB_API_PREFIX}"
    -e "LOG_LEVEL=debug"
    -e "SB_CERTIFICATE_FILE=/root/shadowbox/test.crt"
    -e "SB_PRIVATE_KEY_FILE=/root/shadowbox/test.key"
    -v "${SB_CERTIFICATE_FILE}:/root/shadowbox/test.crt"
    -v "${SB_PRIVATE_KEY_FILE}:/root/shadowbox/test.key"
    -v "${STATE_DIR}:/root/shadowbox/persisted-state"
    --name "${SHADOWBOX_CONTAINER}"
    "${SHADOWBOX_IMAGE}"
  )
  "${DOCKER}" run "${shadowbox_flags[@]}"
  "${DOCKER}" network connect --alias shadowbox "${NET_BLOCKED}" "${SHADOWBOX_CONTAINER}"

  # Client service.
  "${DOCKER}" build --force-rm -t "${CLIENT_IMAGE}" "$(dirname "$0")/client"
  # Use -i to keep the container running.
  "${DOCKER}" run -d --rm -it --network "${NET_BLOCKED}" --name "${CLIENT_CONTAINER}" "${CLIENT_IMAGE}"
}

function remove_containers() {
  # Force remove (-f) running containers and `|| true` to not trigger a shell error
  # in case the container or network doesn't exist.
  "${DOCKER}" rm -f -v "${TARGET_CONTAINER}" || true
  "${DOCKER}" rm -f -v "${SHADOWBOX_CONTAINER}" || true
  "${DOCKER}" rm -f -v "${CLIENT_CONTAINER}" || true
  "${DOCKER}" network rm "${NET_OPEN}" || true
  "${DOCKER}" network rm "${NET_BLOCKED}" || true
}

function cleanup() {
  local -i status=$?
  if ((DEBUG != 1)); then
    remove_containers
    rm -rf "${STATE_DIR}" || echo "Failed to cleanup files at ${STATE_DIR}"
  fi
  return "${status}"
}

# Start a subprocess for trap
(
  set -eu
  ((DEBUG == 1)) && set -x

  # Ensure proper shut down on exit if not in debug mode
  trap "cleanup" EXIT

  # Sets everything up
  export SB_API_PREFIX='TestApiPrefix'
  readonly SB_API_URL="https://shadowbox/${SB_API_PREFIX}"
  export STATE_DIR="${OUTPUT_DIR}/container_state"
  mkdir -p "${STATE_DIR}"
  echo '{"hostname": "shadowbox"}' > "${STATE_DIR}/shadowbox_server_config.json"
  # Make the certificates. This exports SB_CERTIFICATE_FILE and SB_PRIVATE_KEY_FILE.
  # shellcheck source=../scripts/make_test_certificate.sh
  source "$(dirname "$0")/../scripts/make_test_certificate.sh" "${STATE_DIR}"
  setup

  # Wait for target to come up.
  wait_for_resource localhost:10080
  TARGET_IP="$("${DOCKER}" inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${TARGET_CONTAINER}")"
  readonly TARGET_IP

  # Verify that the client cannot access or even resolve the target
  # Exit code 7 is "Failed to connect to host" and 28 is "Connection timed out".
  ("${DOCKER}" exec "${CLIENT_CONTAINER}" curl --silent --connect-timeout 5 "http://${TARGET_IP}" > /dev/null && \
    fail "Client should not have access to target IP") || (($? == 7 || $? == 28))

  # Exit code 6 for "Could not resolve host".  In some environments, curl reports a timeout
  # error (28) instead, which is surprising.  TODO: Investigate and fix.
  ("${DOCKER}" exec "${CLIENT_CONTAINER}" curl --silent --connect-timeout 5 http://target > /dev/null && \
    fail "Client should not have access to target host") || (($? == 6 || $? == 28))

  # Wait for shadowbox to come up.
  wait_for_resource https://localhost:20443/access-keys
  # Verify that the shadowbox can access the target
  "${DOCKER}" exec "${SHADOWBOX_CONTAINER}" wget --spider http://target

  # Create new shadowbox user.
  # TODO(bemasc): Verify that the server is using the right certificate
  NEW_USER_JSON="$(client_curl --insecure -X POST "${SB_API_URL}/access-keys")"
  readonly NEW_USER_JSON
  [[ "${NEW_USER_JSON}" == '{"id":"0"'* ]] || fail "Fail to create user"
  read -r -a SS_USER_ARGUMENTS < <(ss_arguments_for_user "${NEW_USER_JSON}")
  readonly SS_USER_ARGUMENTS

  # Verify that we handle deletions well
  client_curl --insecure -X POST "${SB_API_URL}/access-keys" > /dev/null
  client_curl --insecure -X DELETE "${SB_API_URL}/access-keys/1" > /dev/null

  # Start Shadowsocks client and wait for it to be ready
  declare -ir LOCAL_SOCKS_PORT=5555
  "${DOCKER}" exec -d "${CLIENT_CONTAINER}" \
    /go/bin/go-shadowsocks2 "${SS_USER_ARGUMENTS[@]}" -socks "127.0.0.1:${LOCAL_SOCKS_PORT}" -verbose \
    || fail "Could not start shadowsocks client"
  while ! "${DOCKER}" exec "${CLIENT_CONTAINER}" nc -z 127.0.0.1 "${LOCAL_SOCKS_PORT}"; do
    sleep 0.1
  done

  function test_networking() {
    # Verify the server blocks requests to hosts on private addresses.
    # Exit code 52 is "Empty server response".
    (client_curl -x "socks5h://localhost:${LOCAL_SOCKS_PORT}" "${TARGET_IP}" \
      && fail "Target host in a private network accessible through shadowbox") || (($? == 52))

    # Verify we can retrieve the internet target URL.
    client_curl -x "socks5h://localhost:${LOCAL_SOCKS_PORT}" "${INTERNET_TARGET_URL}" \
      || fail "Could not fetch ${INTERNET_TARGET_URL} through shadowbox."

    # Verify we can't access the URL anymore after the key is deleted
    client_curl --insecure -X DELETE "${SB_API_URL}/access-keys/0" > /dev/null
    # Exit code 56 is "Connection reset by peer".
    (client_curl -x "socks5h://localhost:${LOCAL_SOCKS_PORT}" "${INTERNET_TARGET_URL}" &> /dev/null \
      && fail "Deleted access key is still active") || (($? == 56))
  }

  function test_create_key_with_id() {
    # Verify that we can create key with a given key ID.
    local ACCESS_KEY_JSON
    ACCESS_KEY_JSON="$(client_curl --insecure -X PUT "${SB_API_URL}/access-keys/myKeyId")"
    if [[ "${ACCESS_KEY_JSON}" != *'"id":"myKeyId"'* ]]; then
      fail "Could not create new access key with ID 'myKeyId'"
    fi
  }

  function test_port_for_new_keys() {
    # Verify that we can change the port for new access keys
    client_curl --insecure -X PUT -H "Content-Type: application/json" -d '{"port": 12345}' "${SB_API_URL}/server/port-for-new-access-keys" \
      || fail "Couldn't change the port for new access keys"

    local ACCESS_KEY_JSON
    ACCESS_KEY_JSON="$(client_curl --insecure -X POST "${SB_API_URL}/access-keys" \
      || fail "Couldn't get a new access key after changing port")"

    if [[ "${ACCESS_KEY_JSON}" != *'"port":12345'* ]]; then
      fail "Port for new access keys wasn't changed.  Newly created access key: ${ACCESS_KEY_JSON}"
    fi
  }

  function test_hostname_for_new_keys() {
    # Verify that we can change the hostname for new access keys
    local -r NEW_HOSTNAME="newhostname"
    client_curl --insecure -X PUT -H 'Content-Type: application/json' -d '{"hostname": "'"${NEW_HOSTNAME}"'"}' "${SB_API_URL}/server/hostname-for-access-keys" \
      || fail "Couldn't change hostname for new access keys"

    local ACCESS_KEY_JSON
    ACCESS_KEY_JSON="$(client_curl --insecure -X POST "${SB_API_URL}/access-keys" \
      || fail "Couldn't get a new access key after changing hostname")"

    if [[ "${ACCESS_KEY_JSON}" != *"@${NEW_HOSTNAME}:"* ]]; then
      fail "Hostname for new access keys wasn't changed.  Newly created access key: ${ACCESS_KEY_JSON}"
    fi
  }

  function test_encryption_for_new_keys() {
    # Verify that we can create news keys with custom encryption.
    client_curl --insecure -X POST -H "Content-Type: application/json" -d '{"method":"aes-256-gcm"}' "${SB_API_URL}/access-keys" \
    || fail "Couldn't create a new access key with a custom method"

    local ACCESS_KEY_JSON
    ACCESS_KEY_JSON="$(client_curl --insecure -X GET "${SB_API_URL}/access-keys" \
      || fail "Couldn't get a new access key after changing hostname")"

    if [[ "${ACCESS_KEY_JSON}" != *'"method":"aes-256-gcm"'* ]]; then
      fail "Custom encryption key not taken by new access key: ${ACCESS_KEY_JSON}"
    fi
  }

  function test_default_data_limit() {
    # Verify that we can create default data limits
    client_curl --insecure -X PUT -H 'Content-Type: application/json' -d '{"limit": {"bytes": 1000}}' \
        "${SB_API_URL}/server/access-key-data-limit" \
      || fail "Couldn't create default data limit"
    client_curl --insecure "${SB_API_URL}/server" | grep -q 'accessKeyDataLimit' || fail 'Default data limit not set'

   # Verify that we can remove default data limits
    client_curl --insecure -X DELETE "${SB_API_URL}/server/access-key-data-limit" \
      || fail "Couldn't remove default data limit"
    client_curl --insecure "${SB_API_URL}/server" | grep -vq 'accessKeyDataLimit' || fail 'Default data limit not removed'
  }

  function test_per_key_data_limits() {
    # Verify that we can create per-key data limits
    local ACCESS_KEY_ID
    ACCESS_KEY_ID="$(client_curl --insecure -X POST "${SB_API_URL}/access-keys" | util_jq -re .id \
      || fail "Couldn't get a key to test custom data limits")"

    client_curl --insecure -X PUT -H 'Content-Type: application/json' -d '{"limit": {"bytes": 1000}}' \
        "${SB_API_URL}/access-keys/${ACCESS_KEY_ID}/data-limit" \
      || fail "Couldn't create per-key data limit"
    client_curl --insecure "${SB_API_URL}/access-keys" \
      | util_jq -e ".accessKeys[] | select(.id == \"${ACCESS_KEY_ID}\") | .dataLimit.bytes" \
      || fail 'Per-key data limit not set'

    # Verify that we can remove per-key data limits
    client_curl --insecure -X DELETE "${SB_API_URL}/access-keys/${ACCESS_KEY_ID}/data-limit" \
      || fail "Couldn't remove per-key data limit"
    ! client_curl --insecure "${SB_API_URL}/access-keys" \
      | util_jq -e ".accessKeys[] | select(.id == \"${ACCESS_KEY_ID}\") | .dataLimit.bytes" \
      || fail 'Per-key data limit not removed'
  }

  test_networking
  test_create_key_with_id
  test_port_for_new_keys
  test_hostname_for_new_keys
  test_encryption_for_new_keys
  test_default_data_limit
  test_per_key_data_limits

  # Verify no errors occurred.
  readonly SHADOWBOX_LOG="${OUTPUT_DIR}/shadowbox-log.txt"
  if "${DOCKER}" logs "${SHADOWBOX_CONTAINER}" 2>&1 | tee "${SHADOWBOX_LOG}" | grep -Eq "^E|level=error|ERROR:"; then
    cat "${SHADOWBOX_LOG}"
    fail "Found errors in Shadowbox logs (see above, also saved to ${SHADOWBOX_LOG})"
  fi

  # TODO(fortuna): Test metrics.
  # TODO(fortuna): Verify UDP requests.
)
