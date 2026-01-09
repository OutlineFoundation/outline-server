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

import * as uuidv4 from 'uuid/v4';

import * as json_config from '../infrastructure/json_config';
import {DataLimit} from '../model/access_key';

// Listener configuration for new access keys
export interface ListenerConfig {
  port?: number;
  path?: string;
  webServerPort?: number;
}

export interface ListenersForNewAccessKeys {
  tcp?: ListenerConfig;
  udp?: ListenerConfig;
  websocketStream?: ListenerConfig;
  websocketPacket?: ListenerConfig;
}

// Caddy web server configuration
export interface WebServerConfig {
  enabled?: boolean;
  autoHttps?: boolean;
  email?: string; // For ACME
  domain?: string; // Domain for automatic HTTPS
  apiProxyPath?: string; // Path prefix for API proxy (e.g., "/api")
}

// Serialized format for the server config.
// WARNING: Renaming fields will break backwards-compatibility.
export interface ServerConfigJson {
  // The unique random identifier for this server. Used for shared metrics and staged rollouts.
  serverId?: string;
  // Whether metrics sharing is enabled.
  metricsEnabled?: boolean;
  // The name of this server, as shown in the Outline Manager.
  name?: string;
  // When this server was created. Shown in the Outline Manager and to trigger the metrics opt-in.
  createdTimestampMs?: number;
  // What port number should we use for new access keys?
  portForNewAccessKeys?: number;
  // Listeners configuration for new access keys (supersedes portForNewAccessKeys)
  listenersForNewAccessKeys?: ListenersForNewAccessKeys;
  // Caddy web server configuration for automatic HTTPS
  caddyWebServer?: WebServerConfig;
  // Which staged rollouts we should force enabled or disabled.
  rollouts?: RolloutConfigJson[];
  // We don't serialize the shadowbox version, this is obtained dynamically from node.
  // Public proxy hostname.
  hostname?: string;
  // Default data transfer limit applied to all access keys.
  accessKeyDataLimit?: DataLimit;

  // Experimental configuration options that are expected to be short-lived.
  experimental?: {
    // Whether ASN metric annotation for Prometheus is enabled.
    asnMetricsEnabled?: boolean; // DEPRECATED
  };
}

// Serialized format for rollouts.
// WARNING: Renaming fields will break backwards-compatibility.
export interface RolloutConfigJson {
  // Unique identifier of the rollout.
  id: string;
  // Whether it's forced enabled or disabled. Omit for automatic behavior based on
  // hash(serverId, rolloutId).
  enabled: boolean;
}

export function readServerConfig(filename: string): json_config.JsonConfig<ServerConfigJson> {
  try {
    const config = json_config.loadFileConfig<ServerConfigJson>(filename);
    config.data().serverId = config.data().serverId || uuidv4();
    config.data().metricsEnabled = config.data().metricsEnabled || false;
    config.data().createdTimestampMs = config.data().createdTimestampMs || Date.now();
    config.data().hostname = config.data().hostname || process.env.SB_PUBLIC_IP;
    config.write();
    return config;
  } catch (error) {
    throw new Error(`Failed to read server config at ${filename}: ${error}`);
  }
}
