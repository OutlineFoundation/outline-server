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

import * as randomstring from 'randomstring';

import {Clock} from '../infrastructure/clock';
import {isPortUsed} from '../infrastructure/get_port';
import {JsonConfig} from '../infrastructure/json_config';
import * as logging from '../infrastructure/logging';
import {PrometheusClient} from '../infrastructure/prometheus_scraper';
import {
  AccessKey,
  AccessKeyCreateParams,
  AccessKeyId,
  AccessKeyRepository,
  DataLimit,
  ListenerType,
  ProxyParams,
} from '../model/access_key';
import * as errors from '../model/errors';
import {ShadowsocksServer} from '../model/shadowsocks_server';
import {PrometheusManagerMetrics} from './manager_metrics';

// The format as json of access keys in the config file.
interface AccessKeyStorageJson {
  id: AccessKeyId;
  name: string;
  password: string;
  port: number;
  encryptionMethod?: string;
  dataLimit?: DataLimit;
  listeners?: ListenerType[];
}

// The configuration file format as json.
export interface AccessKeyConfigJson {
  accessKeys?: AccessKeyStorageJson[];
  // Next AccessKeyId to use.
  nextId?: number;
}

// AccessKey implementation with write access enabled on properties that may change.
class ServerAccessKey implements AccessKey {
  reachedDataLimit = false;
  constructor(
    readonly id: AccessKeyId,
    public name: string,
    readonly proxyParams: ProxyParams,
    public dataLimit?: DataLimit,
    public listeners?: ListenerType[]
  ) {}
}

// Generates a random password for Shadowsocks access keys.
function generatePassword(): string {
  // 22 * log2(62) = 131 bits of entropy.
  return randomstring.generate(22);
}

function makeAccessKey(hostname: string, accessKeyJson: AccessKeyStorageJson): AccessKey {
  const proxyParams = {
    hostname,
    portNumber: accessKeyJson.port,
    encryptionMethod: accessKeyJson.encryptionMethod,
    password: accessKeyJson.password,
  };
  return new ServerAccessKey(
    accessKeyJson.id,
    accessKeyJson.name,
    proxyParams,
    accessKeyJson.dataLimit,
    accessKeyJson.listeners
  );
}

function accessKeyToStorageJson(accessKey: AccessKey): AccessKeyStorageJson {
  return {
    id: accessKey.id,
    name: accessKey.name,
    password: accessKey.proxyParams.password,
    port: accessKey.proxyParams.portNumber,
    encryptionMethod: accessKey.proxyParams.encryptionMethod,
    dataLimit: accessKey.dataLimit,
    listeners: accessKey.listeners,
  };
}

function isValidCipher(cipher: string): boolean {
  if (
    ['aes-256-gcm', 'aes-192-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305'].indexOf(cipher) === -1
  ) {
    return false;
  }
  return true;
}

function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}

// AccessKeyRepository that keeps its state in a config file and uses ShadowsocksServer
// to start and stop per-access-key Shadowsocks instances.  Requires external validation
// that portForNewAccessKeys is valid.
export class ServerAccessKeyRepository implements AccessKeyRepository {
  private static DATA_LIMITS_ENFORCEMENT_INTERVAL_MS = 60 * 60 * 1000; // 1h
  private NEW_USER_ENCRYPTION_METHOD = 'chacha20-ietf-poly1305';
  private accessKeys: ServerAccessKey[];

  constructor(
    private portForNewAccessKeys: number,
    private proxyHostname: string,
    private keyConfig: JsonConfig<AccessKeyConfigJson>,
    private shadowsocksServer: ShadowsocksServer,
    private prometheusClient: PrometheusClient,
    private _defaultDataLimit?: DataLimit
  ) {
    if (this.keyConfig.data().accessKeys === undefined) {
      this.keyConfig.data().accessKeys = [];
    }
    if (this.keyConfig.data().nextId === undefined) {
      this.keyConfig.data().nextId = 0;
    }
    this.accessKeys = this.loadAccessKeys();
  }

  // Starts the Shadowsocks server and exposes the access key configuration to the server.
  // Periodically enforces access key limits.
  async start(clock: Clock): Promise<void> {
    const tryEnforceDataLimits = async () => {
      try {
        await this.enforceAccessKeyDataLimits();
      } catch (e) {
        logging.error(`Failed to enforce access key limits: ${e}`);
      }
    };
    await tryEnforceDataLimits();
    await this.updateServer();
    clock.setInterval(
      tryEnforceDataLimits,
      ServerAccessKeyRepository.DATA_LIMITS_ENFORCEMENT_INTERVAL_MS
    );
  }

  private isExistingAccessKeyId(id: AccessKeyId): boolean {
    return this.accessKeys.some((key) => {
      return key.id === id;
    });
  }

  private isExistingAccessKeyPort(port: number): boolean {
    return this.accessKeys.some((key) => {
      return key.proxyParams.portNumber === port;
    });
  }

  private async isPortAvailable(port: number): Promise<boolean> {
    return this.isExistingAccessKeyPort(port) || !(await isPortUsed(port));
  }

  setHostname(hostname: string): void {
    this.proxyHostname = hostname;
  }

  async setPortForNewAccessKeys(port: number): Promise<void> {
    if (!isValidPort(port)) {
      throw new errors.InvalidPortNumber(port);
    }
    if (!(await this.isPortAvailable(port))) {
      throw new errors.PortUnavailable(port);
    }
    this.portForNewAccessKeys = port;
  }

  private generateId(): string {
    let id: AccessKeyId = this.keyConfig.data().nextId.toString();
    this.keyConfig.data().nextId += 1;
    // Users can supply their own access key IDs. This means we always need to
    // verify that any auto-generated key ID hasn't already been used.
    while (this.isExistingAccessKeyId(id)) {
      id = this.keyConfig.data().nextId.toString();
      this.keyConfig.data().nextId += 1;
    }
    return id;
  }

  async createNewAccessKey(params?: AccessKeyCreateParams): Promise<AccessKey> {
    let id = params?.id;
    if (id) {
      if (this.isExistingAccessKeyId(params?.id)) {
        throw new errors.AccessKeyConflict(id);
      }
    } else {
      id = this.generateId();
    }

    const isPasswordConflict = this.listAccessKeys().some(
      (accessKey) => accessKey.proxyParams.password == params?.password
    );

    if (isPasswordConflict) {
      throw new errors.PasswordConflict(id);
    }

    const password = params?.password ?? generatePassword();

    const encryptionMethod = params?.encryptionMethod || this.NEW_USER_ENCRYPTION_METHOD;
    if (encryptionMethod !== this.NEW_USER_ENCRYPTION_METHOD) {
      if (!isValidCipher(encryptionMethod)) {
        throw new errors.InvalidCipher(encryptionMethod);
      }
    }

    const portNumber = params?.portNumber ?? this.portForNewAccessKeys;
    if (portNumber !== this.portForNewAccessKeys) {
      if (!isValidPort(portNumber)) {
        throw new errors.InvalidPortNumber(portNumber);
      }
      if (!(await this.isPortAvailable(portNumber))) {
        throw new errors.PortUnavailable(portNumber);
      }
    }

    const proxyParams = {
      hostname: this.proxyHostname,
      portNumber,
      encryptionMethod,
      password,
    };
    const name = params?.name ?? '';
    const dataLimit = params?.dataLimit;
    const listeners = params?.listeners;
    const accessKey = new ServerAccessKey(id, name, proxyParams, dataLimit, listeners);
    this.accessKeys.push(accessKey);
    this.saveAccessKeys();
    await this.updateServer();
    return accessKey;
  }

  removeAccessKey(id: AccessKeyId) {
    for (let ai = 0; ai < this.accessKeys.length; ai++) {
      const accessKey = this.accessKeys[ai];
      if (accessKey.id === id) {
        this.accessKeys.splice(ai, 1);
        this.saveAccessKeys();
        this.updateServer();
        return;
      }
    }
    throw new errors.AccessKeyNotFound(id);
  }

  getAccessKey(id: AccessKeyId): ServerAccessKey {
    for (const accessKey of this.accessKeys) {
      if (accessKey.id === id) {
        return accessKey;
      }
    }
    throw new errors.AccessKeyNotFound(id);
  }

  listAccessKeys(): AccessKey[] {
    return [...this.accessKeys]; // Return a copy of the access key array.
  }

  renameAccessKey(id: AccessKeyId, name: string) {
    const accessKey = this.getAccessKey(id);
    accessKey.name = name;
    this.saveAccessKeys();
  }

  setAccessKeyDataLimit(id: AccessKeyId, limit: DataLimit): void {
    this.getAccessKey(id).dataLimit = limit;
    this.saveAccessKeys();
    this.enforceAccessKeyDataLimits();
  }

  removeAccessKeyDataLimit(id: AccessKeyId): void {
    delete this.getAccessKey(id).dataLimit;
    this.saveAccessKeys();
    this.enforceAccessKeyDataLimits();
  }

  get defaultDataLimit(): DataLimit | undefined {
    return this._defaultDataLimit;
  }

  setDefaultDataLimit(limit: DataLimit): void {
    this._defaultDataLimit = limit;
    this.enforceAccessKeyDataLimits();
  }

  removeDefaultDataLimit(): void {
    delete this._defaultDataLimit;
    this.enforceAccessKeyDataLimits();
  }

  setAccessKeyListeners(id: AccessKeyId, listeners: ListenerType[]): void {
    this.getAccessKey(id).listeners = listeners;
    this.saveAccessKeys();
    this.updateServer();
  }

  setListenersForAllKeys(listeners: ListenerType[]): void {
    for (const accessKey of this.accessKeys) {
      accessKey.listeners = listeners;
    }
    this.saveAccessKeys();
    this.updateServer();
  }

  // Compares access key usage with collected metrics, marking them as under or over limit.
  // Updates access key data usage.
  async enforceAccessKeyDataLimits() {
    const metrics = new PrometheusManagerMetrics(this.prometheusClient);
    const bytesTransferredById = (await metrics.getOutboundByteTransfer({hours: 30 * 24}))
      .bytesTransferredByUserId;
    let limitStatusChanged = false;
    for (const accessKey of this.accessKeys) {
      const usageBytes = bytesTransferredById[accessKey.id] ?? 0;
      const oldReachedDataLimit = accessKey.reachedDataLimit;
      let limitBytes = (accessKey.dataLimit ?? this._defaultDataLimit)?.bytes;
      if (limitBytes === undefined) {
        limitBytes = Number.POSITIVE_INFINITY;
      }
      accessKey.reachedDataLimit = usageBytes >= limitBytes;
      limitStatusChanged = accessKey.reachedDataLimit !== oldReachedDataLimit || limitStatusChanged;
    }
    if (limitStatusChanged) {
      await this.updateServer();
    }
  }

  private updateServer(): Promise<void> {
    const serverAccessKeys = this.accessKeys
      .filter((key) => !key.reachedDataLimit)
      .map((key) => {
        return {
          id: key.id,
          port: key.proxyParams.portNumber,
          cipher: key.proxyParams.encryptionMethod,
          secret: key.proxyParams.password,
          listeners: key.listeners, // Pass listeners to enable WebSocket config generation
        };
      });
    return this.shadowsocksServer.update(serverAccessKeys);
  }

  private loadAccessKeys(): AccessKey[] {
    return this.keyConfig.data().accessKeys.map((key) => makeAccessKey(this.proxyHostname, key));
  }

  private saveAccessKeys() {
    this.keyConfig.data().accessKeys = this.accessKeys.map((key) => accessKeyToStorageJson(key));
    this.keyConfig.write();
  }
}
