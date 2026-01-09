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

export type AccessKeyId = string;

// Listener types that an access key can use
export type ListenerType = 'tcp' | 'udp' | 'websocket-stream' | 'websocket-packet';

// Parameters needed to access a Shadowsocks proxy.
export interface ProxyParams {
  // Hostname of the proxy
  readonly hostname: string;
  // Number of the port where the Shadowsocks service is running.
  readonly portNumber: number;
  // The Shadowsocks encryption method being used.
  readonly encryptionMethod: string;
  // The password for the encryption.
  readonly password: string;
}

// Data transfer allowance, measured in bytes. Must be a serializable JSON object.
export interface DataLimit {
  readonly bytes: number;
}

// AccessKey is what admins work with. It gives ProxyParams a name and identity.
export interface AccessKey {
  // The unique identifier for this access key.
  readonly id: AccessKeyId;
  // Admin-controlled, editable name for this access key.
  readonly name: string;
  // Parameters to access the proxy
  readonly proxyParams: ProxyParams;
  // Whether the access key has reached the data transfer limit.
  readonly reachedDataLimit: boolean;
  // The key's current data limit.  If it exists, it overrides the server default data limit.
  readonly dataLimit?: DataLimit;
  // Listeners enabled for this access key
  readonly listeners?: ListenerType[];
}

export interface AccessKeyCreateParams {
  // The unique identifier to give the access key. Throws if it exists.
  readonly id?: AccessKeyId;
  // The encryption method to use for the access key.
  readonly encryptionMethod?: string;
  // The name to give the access key.
  readonly name?: string;
  // The password to use for the access key.
  readonly password?: string;
  // The data transfer limit to apply to the access key.
  readonly dataLimit?: DataLimit;
  // The port number to use for the access key.
  readonly portNumber?: number;
  // Listeners to enable for this access key.
  readonly listeners?: ListenerType[];
}

export interface AccessKeyRepository {
  // Creates a new access key. Parameters are chosen automatically if not provided.
  createNewAccessKey(params?: AccessKeyCreateParams): Promise<AccessKey>;
  // Removes the access key given its id. Throws on failure.
  removeAccessKey(id: AccessKeyId);
  // Returns the access key with the given id. Throws on failure.
  getAccessKey(id: AccessKeyId): AccessKey;
  // Lists all existing access keys
  listAccessKeys(): AccessKey[];
  // Changes the port for new access keys.
  setPortForNewAccessKeys(port: number): Promise<void>;
  // Changes the hostname for access keys.
  setHostname(hostname: string): void;
  // Apply the specified update to the specified access key. Throws on failure.
  renameAccessKey(id: AccessKeyId, name: string): void;
  // Sets a data transfer limit for all access keys.
  setDefaultDataLimit(limit: DataLimit): void;
  // Removes the access key data transfer limit.
  removeDefaultDataLimit(): void;
  // Sets access key `id` to use the given custom data limit.
  setAccessKeyDataLimit(id: AccessKeyId, limit: DataLimit): void;
  // Removes the custom data limit from access key `id`.
  removeAccessKeyDataLimit(id: AccessKeyId): void;
}
