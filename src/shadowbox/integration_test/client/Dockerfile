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

# Alpine 3.19 curl is using the c-ares resolver instead of the system resolver,
# which caused DNS issues. Upgrade once the Alpine image includes the fix. See
# https://github.com/OutlineFoundation/outline-server/pull/1566.
FROM docker.io/golang:1-alpine3.18

# curl for fetching pages using the local proxy
RUN apk add --no-cache curl git
RUN go install github.com/shadowsocks/go-shadowsocks2@v0.1.5

ENTRYPOINT [ "sh" ]
