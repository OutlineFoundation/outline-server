# 1.7.2

- Fixes
  - Fix reporting of country metrics and improve logging output (https://github.com/OutlineFoundation/outline-server/pull/1242)

# 1.7.1

- Fixes
  - Corner case of isPortUsed that could result in infinite restart loop (https://github.com/OutlineFoundation/outline-server/pull/1238)
  - Prevent excessive logging (https://github.com/OutlineFoundation/outline-server/pull/1232)

# 1.7.0

- Features
  - Add encryption cipher selection to create access key API (https://github.com/OutlineFoundation/outline-server/pull/1002)
  - Make access key secrets longer (https://github.com/OutlineFoundation/outline-server/pull/1098)
- Fixes
  - Race condition on concurrent API calls (https://github.com/OutlineFoundation/outline-server/pull/995)
- Upgrades (https://github.com/OutlineFoundation/outline-server/pull/1211)
  - Base image to `node:16.18.0-alpine3.16`
  - outline-ss-server from 1.3.5 to [1.4.0](https://github.com/OutlineFoundation/outline-ss-server/releases/tag/v1.4.0)
  - Prometheus from 2.33.5 to [2.37.1](https://github.com/prometheus/prometheus/releases/tag/v2.37.1)
