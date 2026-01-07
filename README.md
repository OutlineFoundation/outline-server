# Outline Server

![Build and Test](https://github.com/OutlineFoundation/outline-server/actions/workflows/build_and_test_debug.yml/badge.svg?branch=master) [![Mattermost](https://badgen.net/badge/Mattermost/Outline%20Community/blue)](https://community.internetfreedomfestival.org/community/channels/outline-community) [![Reddit](https://badgen.net/badge/Reddit/r%2Foutlinevpn/orange)](https://www.reddit.com/r/outlinevpn/)

Outline Server is the component that provides the Shadowsocks service (via [outline-ss-server](https://github.com/OutlineFoundation/tunnel-server/)) and a service management API. You can deploy this server directly following simple instructions in this repository, or if you prefer a ready-to-use graphical interface you can use the [Outline Manager](https://github.com/OutlineFoundation/outline-apps/).

**Components:**

- **Outline Server** ([`src/shadowbox`](src/shadowbox)): The core proxy server that runs and manages [outline-ss-server](https://github.com/OutlineFoundation/tunnel-server/), a Shadowsocks backend. It provides a REST API for access key management.

- **Metrics Server** ([`src/metrics_server`](src/metrics_server)): A REST service for optional, anonymous metrics sharing.

**Join the Outline Community** by signing up for the [IFF Mattermost](https://wiki.digitalrights.community/index.php?title=IFF_Mattermost)!

## Shadowsocks and Anti-Censorship

Outline's use of Shadowsocks means it benefits from ongoing improvements that strengthen its resistance against detection and blocking.

**Key Protections:**

- **AEAD ciphers** are mandatory.
- **Probing resistance** mitigates detection techniques.
- **Protection against replayed data.**
- **Variable packet sizes** to hinder identification.

See [Shadowsocks resistance against detection and blocking](docs/shadowsocks.md).

## Installation

**Prerequisites**

- [Node](https://nodejs.org/en/download/) LTS (`lts/hydrogen`, version `18.16.0`)
- [NPM](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) (version `9.5.1`)
- [Go](https://go.dev/dl/) 1.21+

1. **Install dependencies**

   ```sh
   npm install
   ```

1. **Start the server**

   ```sh
   ./task shadowbox:start
   ```

   Exploring further options:

   - **Refer to the README:** Find additional configuration and usage options in the core server's [`README`](src/shadowbox/README.md).
   - **Learn about the build system:** For in-depth build system information, consult the [contributing guide](CONTRIBUTING.md).

1. **To clean up**

   ```sh
   ./task clean
   ```
