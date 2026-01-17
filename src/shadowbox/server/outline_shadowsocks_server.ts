// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as child_process from 'child_process';
import * as jsyaml from 'js-yaml';
import * as mkdirp from 'mkdirp';
import * as path from 'path';

import * as file from '../infrastructure/file';
import * as logging from '../infrastructure/logging';
import {ListenerType} from '../model/access_key';
import {
  ListenerSettings,
  ShadowsocksAccessKey,
  ShadowsocksServer,
} from '../model/shadowsocks_server';

// Extended interface for access keys with listeners
export interface ShadowsocksAccessKeyWithListeners extends ShadowsocksAccessKey {
  listeners?: string[];
}

// Configuration types for outline-ss-server
interface LegacyConfig {
  keys: ShadowsocksAccessKey[];
}

interface WebSocketListener {
  type: 'websocket-stream' | 'websocket-packet';
  web_server: string;
  path: string;
}

interface TcpUdpListener {
  type: 'tcp' | 'udp';
  address: string;
}

interface ServiceConfig {
  listeners: Array<WebSocketListener | TcpUdpListener>;
  keys: Array<{
    id: string;
    cipher: string;
    secret: string;
  }>;
}

interface WebSocketConfig {
  web?: {
    servers: Array<{
      id: string;
      listen: string[];
    }>;
  };
  services: ServiceConfig[];
}

type ServerConfig = LegacyConfig | WebSocketConfig;

// Runs outline-ss-server.
export class OutlineShadowsocksServer implements ShadowsocksServer {
  private ssProcess: child_process.ChildProcess;
  private ipCountryFilename?: string;
  private ipAsnFilename?: string;
  private isAsnMetricsEnabled = false;
  private isReplayProtectionEnabled = false;
  private listenerSettings: ListenerSettings = {};

  /**
   * @param binaryFilename The location for the outline-ss-server binary.
   * @param configFilename The location for the outline-ss-server config.
   * @param verbose Whether to run the server in verbose mode.
   * @param metricsLocation The location from where to serve the Prometheus data metrics.
   */
  constructor(
    private readonly binaryFilename: string,
    private readonly configFilename: string,
    private readonly verbose: boolean,
    private readonly metricsLocation: string
  ) {}

  /**
   * Configures the Shadowsocks Server with country data to annotate Prometheus data metrics.
   * @param ipCountryFilename The location of the ip-country.mmdb IP-to-country database file.
   */
  configureCountryMetrics(ipCountryFilename: string): OutlineShadowsocksServer {
    this.ipCountryFilename = ipCountryFilename;
    return this;
  }

  /**
   * Configures the Shadowsocks Server with ASN data to annotate Prometheus data metrics.
   * @param ipAsnFilename The location  of the ip-asn.mmdb IP-to-ASN database file.
   */
  configureAsnMetrics(ipAsnFilename: string): OutlineShadowsocksServer {
    this.ipAsnFilename = ipAsnFilename;
    return this;
  }

  enableReplayProtection(): OutlineShadowsocksServer {
    this.isReplayProtectionEnabled = true;
    return this;
  }

  /**
   * Configures WebSocket support for the Shadowsocks server.
   * @param webServerPort The port for the internal WebSocket server to listen on.
   * @param tcpPath Optional path to expose TCP over WebSocket.
   * @param udpPath Optional path to expose UDP over WebSocket.
   */
  configureWebSocket(
    webServerPort: number,
    tcpPath = '/tcp',
    udpPath = '/udp'
  ): OutlineShadowsocksServer {
    return this.configureListeners({
      websocketStream: {webServerPort, path: tcpPath},
      websocketPacket: {webServerPort, path: udpPath},
    });
  }

  configureListeners(listeners: ListenerSettings | undefined): OutlineShadowsocksServer {
    if (!listeners) {
      this.listenerSettings = {};
      return this;
    }

    const stream = listeners.websocketStream ? {...listeners.websocketStream} : undefined;
    const packet = listeners.websocketPacket ? {...listeners.websocketPacket} : undefined;

    // If only one listener specifies the web server port, share it across both listeners.
    const sharedPort = stream?.webServerPort ?? packet?.webServerPort;
    if (stream && sharedPort !== undefined && stream.webServerPort === undefined) {
      stream.webServerPort = sharedPort;
    }
    if (packet && sharedPort !== undefined && packet.webServerPort === undefined) {
      packet.webServerPort = sharedPort;
    }

    this.listenerSettings = {
      websocketStream: stream,
      websocketPacket: packet,
    };
    return this;
  }

  // Promise is resolved after the outline-ss-config config is updated and the SIGHUP sent.
  // Keys may not be active yet.
  // TODO(fortuna): Make promise resolve when keys are ready.
  update(keys: ShadowsocksAccessKey[]): Promise<void> {
    return this.writeConfigFile(keys).then(() => {
      if (!this.ssProcess) {
        this.start();
        return Promise.resolve();
      } else {
        this.ssProcess.kill('SIGHUP');
      }
    });
  }

  private writeConfigFile(keys: ShadowsocksAccessKey[]): Promise<void> {
    return new Promise((resolve, reject) => {
      // Check if any key has WebSocket listeners
      const extendedKeys = keys as ShadowsocksAccessKeyWithListeners[];

      // Debug logging
      logging.info(`Writing config for ${keys.length} keys`);
      extendedKeys.forEach((key) => {
        if (key.listeners) {
          logging.info(`Key ${key.id} has listeners: ${JSON.stringify(key.listeners)}`);
        }
      });

      const hasWebSocketKeys = extendedKeys.some(
        (key) =>
          key.listeners &&
          (key.listeners.indexOf('websocket-stream') !== -1 ||
            key.listeners.indexOf('websocket-packet') !== -1)
      );

      logging.info(`WebSocket keys detected: ${hasWebSocketKeys}`);

      let config: ServerConfig;

      if (hasWebSocketKeys) {
        // Use new format with WebSocket support
        config = this.generateWebSocketConfig(extendedKeys);
      } else {
        // Use legacy format for backward compatibility
        const keysJson = {keys: [] as ShadowsocksAccessKey[]};
        for (const key of keys) {
          if (!isAeadCipher(key.cipher)) {
            logging.error(
              `Cipher ${key.cipher} for access key ${key.id} is not supported: use an AEAD cipher instead.`
            );
            continue;
          }
          keysJson.keys.push(key);
        }
        config = keysJson;
      }

      mkdirp.sync(path.dirname(this.configFilename));

      try {
        file.atomicWriteFileSync(this.configFilename, jsyaml.safeDump(config, {sortKeys: true}));
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  private getWebSocketSettings() {
    const stream = this.listenerSettings.websocketStream ?? {};
    const packet = this.listenerSettings.websocketPacket ?? {};
    const webServerPort = stream.webServerPort ?? packet.webServerPort ?? 8080;
    const tcpPath = stream.path ?? '/tcp';
    const udpPath = packet.path ?? '/udp';
    return {webServerPort, tcpPath, udpPath};
  }

  private generateWebSocketConfig(keys: ShadowsocksAccessKeyWithListeners[]): WebSocketConfig {
    const {webServerPort, tcpPath, udpPath} = this.getWebSocketSettings();
    const webServerId = 'outline-ws-server';

    type ListenerDescriptor = WebSocketListener | TcpUdpListener;
    const isWebSocketListener = (listener: ListenerDescriptor): listener is WebSocketListener => {
      return listener.type === 'websocket-stream' || listener.type === 'websocket-packet';
    };

    interface ServiceGroup {
      listeners: ListenerDescriptor[];
      keys: ShadowsocksAccessKeyWithListeners[];
    }

    const serviceGroups = new Map<string, ServiceGroup>();

    for (const key of keys) {
      if (!isAeadCipher(key.cipher)) {
        logging.error(
          `Cipher ${key.cipher} for access key ${key.id} is not supported: use an AEAD cipher instead.`
        );
        continue;
      }

      const listenerSet = new Set<ListenerType>(
        (key.listeners as ListenerType[] | undefined) ?? ['tcp', 'udp']
      );
      if (listenerSet.size === 0) {
        listenerSet.add('tcp');
        listenerSet.add('udp');
      }

      const listenersForKey: ListenerDescriptor[] = [];

      if (listenerSet.has('tcp')) {
        listenersForKey.push({
          type: 'tcp',
          address: `[::]:${key.port}`,
        });
      }
      if (listenerSet.has('udp')) {
        listenersForKey.push({
          type: 'udp',
          address: `[::]:${key.port}`,
        });
      }
      if (listenerSet.has('websocket-stream')) {
        listenersForKey.push({
          type: 'websocket-stream',
          web_server: webServerId,
          path: tcpPath,
        });
      }
      if (listenerSet.has('websocket-packet')) {
        listenersForKey.push({
          type: 'websocket-packet',
          web_server: webServerId,
          path: udpPath,
        });
      }

      if (listenersForKey.length === 0) {
        logging.warn(
          `Access key ${key.id} has no listeners configured; assigning default TCP/UDP listeners.`
        );
        listenersForKey.push(
          {type: 'tcp', address: `[::]:${key.port}`},
          {type: 'udp', address: `[::]:${key.port}`}
        );
      }

      const signatureParts = listenersForKey
        .map((listener) => {
          if (!isWebSocketListener(listener)) {
            return `${listener.type}:${listener.address}`;
          }
          return `${listener.type}:${listener.path}`;
        })
        .sort();
      const groupKey = signatureParts.join('|');

      if (!serviceGroups.has(groupKey)) {
        const listenersClone = listenersForKey.map((listener) => ({...listener}));
        serviceGroups.set(groupKey, {listeners: listenersClone as ListenerDescriptor[], keys: []});
      }
      serviceGroups.get(groupKey)!.keys.push(key);
    }

    const config: WebSocketConfig = {
      services: [],
    };

    const needsWebServer = Array.from(serviceGroups.values()).some((group) =>
      group.listeners.some(
        (listener) => listener.type === 'websocket-stream' || listener.type === 'websocket-packet'
      )
    );

    if (needsWebServer) {
      config.web = {
        servers: [
          {
            id: webServerId,
            listen: [`127.0.0.1:${webServerPort}`],
          },
        ],
      };
    }

    for (const group of serviceGroups.values()) {
      const service: ServiceConfig = {
        listeners: group.listeners.map((listener) => ({...listener})),
        keys: group.keys.map((k) => ({
          id: k.id,
          cipher: k.cipher,
          secret: k.secret,
        })),
      };
      config.services.push(service);
    }

    return config;
  }

  /**
   * Generates dynamic access key configuration as a JSON object for WebSocket-enabled keys.
   * This object can be serialized to YAML for use with Outline Client v1.15.0+.
   * @param proxyParams The proxy parameters containing cipher and password
   * @param domain The WebSocket server domain
   * @param tcpPath The path for TCP over WebSocket
   * @param udpPath The path for UDP over WebSocket
   * @param tls Whether to use TLS (wss) or not (ws)
   * @param listeners Optional list of listener types to include
   * @returns The configuration object, or null if no WebSocket listeners
   */
  generateDynamicAccessKeyConfig(
    proxyParams: {encryptionMethod: string; password: string},
    domain: string,
    tcpPath: string,
    udpPath: string,
    tls: boolean,
    listeners?: ListenerType[]
  ): Record<string, unknown> | null {
    if (!domain) {
      return null;
    }

    const listenerSet = new Set<ListenerType>(
      listeners ?? ['websocket-stream', 'websocket-packet']
    );
    const includeStream = listenerSet.has('websocket-stream');
    const includePacket = listenerSet.has('websocket-packet');

    if (!includeStream && !includePacket) {
      logging.warn('Dynamic access key config requested without WebSocket listeners; skipping.');
      return null;
    }

    const protocol = tls ? 'wss' : 'ws';
    const transportType = includeStream && includePacket ? 'tcpudp' : includeStream ? 'tcp' : 'udp';

    const transport: Record<string, unknown> = {
      $type: transportType,
    };

    if (includeStream) {
      transport['tcp'] = {
        $type: 'shadowsocks',
        endpoint: {
          $type: 'websocket',
          url: `${protocol}://${domain}${tcpPath}`,
        },
        cipher: proxyParams.encryptionMethod,
        secret: proxyParams.password,
      };
    }

    if (includePacket) {
      transport['udp'] = {
        $type: 'shadowsocks',
        endpoint: {
          $type: 'websocket',
          url: `${protocol}://${domain}${udpPath}`,
        },
        cipher: proxyParams.encryptionMethod,
        secret: proxyParams.password,
      };
    }

    return {transport};
  }

  /**
   * Generates dynamic access key YAML content for a specific access key with WebSocket support.
   * @param proxyParams The proxy parameters containing cipher and password
   * @param domain The WebSocket server domain
   * @param tcpPath The path for TCP over WebSocket
   * @param udpPath The path for UDP over WebSocket
   * @param tls Whether to use TLS (wss) or not (ws)
   * @param listeners Optional list of listener types to include
   * @returns The YAML content as a string, or null if no WebSocket listeners
   */
  generateDynamicAccessKeyYaml(
    proxyParams: {encryptionMethod: string; password: string},
    domain: string,
    tcpPath: string,
    udpPath: string,
    tls: boolean,
    listeners?: ListenerType[]
  ): string | null {
    const config = this.generateDynamicAccessKeyConfig(
      proxyParams,
      domain,
      tcpPath,
      udpPath,
      tls,
      listeners
    );

    if (!config) {
      return null;
    }

    // Use specific YAML options to ensure proper formatting
    return jsyaml.dump(config, {
      indent: 2,
      lineWidth: -1, // Don't wrap long lines
      noRefs: true, // Don't use references
      sortKeys: false, // Preserve key order
      styles: {
        '!!null': 'canonical', // Use ~ for null values
      },
    });
  }

  private start() {
    const commandArguments = ['-config', this.configFilename, '-metrics', this.metricsLocation];
    if (this.ipCountryFilename) {
      commandArguments.push('-ip_country_db', this.ipCountryFilename);
    }
    if (this.ipAsnFilename) {
      commandArguments.push('-ip_asn_db', this.ipAsnFilename);
    }
    if (this.verbose) {
      commandArguments.push('-verbose');
    }
    if (this.isReplayProtectionEnabled) {
      commandArguments.push('--replay_history=10000');
    }
    logging.info('======== Starting Outline Shadowsocks Service ========');
    logging.info(`${this.binaryFilename} ${commandArguments.map((a) => `"${a}"`).join(' ')}`);
    this.ssProcess = child_process.spawn(this.binaryFilename, commandArguments);
    this.ssProcess.on('error', (error) => {
      logging.error(`Error spawning outline-ss-server: ${error}`);
    });
    this.ssProcess.on('exit', (code, signal) => {
      logging.info(`outline-ss-server has exited with error. Code: ${code}, Signal: ${signal}`);
      logging.info('Restarting');
      this.start();
    });
    // This exposes the outline-ss-server output on the docker logs.
    // TODO(fortuna): Consider saving the output and expose it through the manager service.
    this.ssProcess.stdout.pipe(process.stdout);
    this.ssProcess.stderr.pipe(process.stderr);
  }
}

// List of AEAD ciphers can be found at https://shadowsocks.org/en/spec/AEAD-Ciphers.html
function isAeadCipher(cipherAlias: string) {
  cipherAlias = cipherAlias.toLowerCase();
  return cipherAlias.endsWith('gcm') || cipherAlias.endsWith('poly1305');
}
