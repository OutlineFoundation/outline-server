// Copyright 2024 The Outline Authors
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
import * as path from 'path';

import * as mkdirp from 'mkdirp';
import * as yaml from 'js-yaml';

import * as file from '../infrastructure/file';
import * as logging from '../infrastructure/logging';
import {AccessKey, ListenerType} from '../model/access_key';
import {WebServerConfig, ListenerConfig, ListenersConfig} from './server_config';

export interface OutlineCaddyConfigPayload {
  accessKeys: AccessKey[];
  listeners?: ListenersConfig;
  caddyConfig?: WebServerConfig;
  hostname?: string;
  apiPort?: number; // Internal API port for reverse proxy
}

export interface OutlineCaddyController {
  applyConfig(payload: OutlineCaddyConfigPayload): Promise<void>;
  stop(): Promise<void>;
}

interface WebSocketListenerSettings {
  tcpPath: string;
  udpPath: string;
  listenPort: number;
}

interface CaddyConfig {
  logging?: unknown;
  apps: Record<string, unknown>;
}

export class OutlineCaddyServer implements OutlineCaddyController {
  private process?: child_process.ChildProcess;
  private readonly restartDelayMs = 1000;
  private shouldRun = false;
  private currentConfigHash?: string;

  constructor(
    private readonly binaryFilename: string,
    private readonly configFilename: string,
    private readonly verbose: boolean
  ) {}

  async applyConfig(payload: OutlineCaddyConfigPayload): Promise<void> {
    const {enabled = false} = payload.caddyConfig || {};
    if (!enabled) {
      await this.stop();
      this.currentConfigHash = undefined;
      return;
    }

    const listenerSettings = this.getWebSocketSettings(
      payload.listeners?.websocketStream,
      payload.listeners?.websocketPacket
    );
    const websocketKeys = this.getWebSocketKeys(payload.accessKeys);

    if (websocketKeys.length === 0) {
      logging.warn('Caddy web server enabled but no WebSocket-enabled access keys found.');
    }

    const configObject = this.buildConfig(payload, listenerSettings, websocketKeys);
    const configYaml = yaml.dump(configObject);
    if (configYaml === this.currentConfigHash) {
      // No changes; nothing to do.
      return;
    }

    mkdirp.sync(path.dirname(this.configFilename));
    file.atomicWriteFileSync(this.configFilename, configYaml);
    this.currentConfigHash = configYaml;
    this.shouldRun = true;
    await this.ensureStarted();
  }

  async stop(): Promise<void> {
    this.shouldRun = false;
    if (!this.process) {
      return;
    }
    const proc = this.process;
    this.process = undefined;
    await new Promise<void>((resolve) => {
      proc.once('exit', () => resolve());
      proc.kill('SIGTERM');
      // Fallback in case the process ignores SIGTERM.
      setTimeout(() => {
        if (!proc.killed) {
          proc.kill('SIGKILL');
        }
      }, 5000);
    });
  }

  private async ensureStarted(): Promise<void> {
    if (this.process) {
      return;
    }
    try {
      await this.start();
    } catch (error) {
      logging.error(`Failed to start outline-caddy: ${error}`);
      throw error;
    }
  }

  private start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const args = ['run', '--config', this.configFilename, '--adapter', 'yaml', '--watch'];
      logging.info(`Starting outline-caddy with command: ${this.binaryFilename} ${args.join(' ')}`);
      const proc = child_process.spawn(this.binaryFilename, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const onSpawnError = (error: Error) => {
        if (this.process === proc) {
          this.process = undefined;
        }
        proc.removeAllListeners();
        reject(error);
      };

      proc.once('error', onSpawnError);
      proc.once('spawn', () => {
        this.process = proc;
        proc.off('error', onSpawnError);
        resolve();
      });

      proc.stdout?.on('data', (data: Buffer) => {
        logging.info(`[outline-caddy] ${data.toString().trimEnd()}`);
      });
      proc.stderr?.on('data', (data: Buffer) => {
        logging.error(`[outline-caddy] ${data.toString().trimEnd()}`);
      });

      proc.on('exit', (code, signal) => {
        this.process = undefined;
        const message = `outline-caddy exited with code ${code}, signal ${signal}`;
        if (this.shouldRun) {
          logging.warn(`${message}. Restarting.`);
          setTimeout(() => {
            if (this.shouldRun) {
              this.start().catch((error) => {
                logging.error(`Failed to restart outline-caddy: ${error}`);
              });
            }
          }, this.restartDelayMs);
        } else {
          logging.info(message);
        }
      });
    });
  }

  private getWebSocketKeys(accessKeys: AccessKey[]) {
    return accessKeys
      .filter((key) => {
        const listeners = key.listeners || [];
        return (
          listeners.includes('websocket-stream' as ListenerType) ||
          listeners.includes('websocket-packet' as ListenerType)
        );
      })
      .map((key) => ({
        id: key.id,
        cipher: key.proxyParams.encryptionMethod,
        secret: key.proxyParams.password,
        listeners: key.listeners || [],
      }));
  }

  private getWebSocketSettings(
    streamListener?: ListenerConfig,
    packetListener?: ListenerConfig
  ): WebSocketListenerSettings {
    const tcpPath = this.normalisePath(streamListener?.path ?? '/tcp');
    const udpPath = this.normalisePath(packetListener?.path ?? '/udp');
    const listenPort = streamListener?.webServerPort ?? packetListener?.webServerPort ?? 8080;
    return {tcpPath, udpPath, listenPort};
  }

  private normalisePath(pathValue: string): string {
    if (!pathValue.startsWith('/')) {
      return `/${pathValue}`;
    }
    return pathValue;
  }

  private buildConfig(
    payload: OutlineCaddyConfigPayload,
    listenerSettings: WebSocketListenerSettings,
    websocketKeys: Array<{id: string; cipher: string; secret: string; listeners: ListenerType[]}>
  ): CaddyConfig {
    const {caddyConfig, hostname} = payload;
    const requestedDomain = caddyConfig?.domain?.trim() || hostname;
    let autoHttps = !!caddyConfig?.autoHttps;
    if (autoHttps && !requestedDomain) {
      logging.warn('Caddy auto HTTPS requested but no domain configured; disabling auto HTTPS.');
      autoHttps = false;
    }
    const domain = requestedDomain;
    const listenAddresses = autoHttps ? [':80', ':443'] : [`:${listenerSettings.listenPort}`];

    const hasStreamRoute =
      websocketKeys.length === 0 ||
      websocketKeys.some((key) => key.listeners.includes('websocket-stream'));
    const hasPacketRoute =
      websocketKeys.length === 0 ||
      websocketKeys.some((key) => key.listeners.includes('websocket-packet'));

    const routes = [];
    if (hasStreamRoute) {
      routes.push(this.buildWebsocketRoute(listenerSettings.tcpPath, 'stream', domain));
    }
    if (hasPacketRoute) {
      routes.push(this.buildWebsocketRoute(listenerSettings.udpPath, 'packet', domain));
    }

    // Add API proxy route if configured
    if (caddyConfig?.apiProxyPath && payload.apiPort) {
      routes.push(this.buildApiProxyRoute(caddyConfig.apiProxyPath, payload.apiPort, domain));
    }

    const connectionHandler = {
      name: 'outline-ws',
      handle: {
        handler: 'shadowsocks',
        keys: websocketKeys.map((key) => ({
          id: key.id,
          cipher: key.cipher,
          secret: key.secret,
        })),
      },
    };

    const httpServer: Record<string, unknown> = {
      listen: listenAddresses,
      routes,
      trusted_proxies: {
        source: 'static',
        ranges: ['127.0.0.1', '::1'],
      },
      client_ip_headers: [
        'X-Forwarded-For',
        'X-Original-Forwarded-For',
        'Forwarded-For',
        'Forwarded',
        'Client-IP',
        'CF-Connecting-IP',
        'X-Real-IP',
        'X-Client-IP',
        'True-Client-IP',
      ],
    };

    if (!autoHttps) {
      httpServer['automatic_https'] = {disable: true};
    }

    const apps: Record<string, unknown> = {
      outline: {
        shadowsocks: {
          replay_history: 10000,
        },
        connection_handlers: [connectionHandler],
      },
      http: {
        servers: {
          'outline-websocket': httpServer,
        },
      },
    };

    if (autoHttps && domain) {
      apps['tls'] = {
        automation: {
          policies: [
            {
              subjects: [domain],
              issuers: [
                {
                  module: 'acme',
                  ...(caddyConfig?.email ? {email: caddyConfig.email} : {}),
                },
              ],
            },
          ],
        },
      };
    }

    if (this.verbose) {
      return {
        logging: {
          logs: {
            default: {
              level: 'DEBUG',
            },
          },
        },
        apps,
      };
    }

    return {apps};
  }

  private buildWebsocketRoute(pathValue: string, type: 'stream' | 'packet', domain?: string) {
    const match: Record<string, unknown> = {
      path: [pathValue],
    };
    if (domain) {
      match['host'] = [domain];
    }
    return {
      match: [match],
      handle: [
        {
          handler: 'websocket2layer4',
          type,
          connection_handler: 'outline-ws',
        },
      ],
    };
  }

  private buildApiProxyRoute(pathPrefix: string, apiPort: number, domain?: string) {
    const normalizedPrefix = this.normalisePath(pathPrefix);
    const match: Record<string, unknown> = {
      path: [`${normalizedPrefix}/*`],
    };
    if (domain) {
      match['host'] = [domain];
    }
    return {
      match: [match],
      handle: [
        {
          handler: 'rewrite',
          strip_path_prefix: normalizedPrefix,
        },
        {
          handler: 'reverse_proxy',
          upstreams: [{dial: `localhost:${apiPort}`}],
          transport: {
            protocol: 'http',
            tls: {
              insecure_skip_verify: true, // Skip verification for self-signed cert
            },
          },
        },
      ],
    };
  }
}
