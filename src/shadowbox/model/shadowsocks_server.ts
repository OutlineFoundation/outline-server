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

// Parameters required to identify and authenticate connections to a Shadowsocks server.
export interface ShadowsocksAccessKey {
  id: string;
  port: number;
  cipher: string;
  secret: string;
}

export interface ListenerSettings {
  websocketStream?: {
    path?: string;
    webServerPort?: number;
  };
  websocketPacket?: {
    path?: string;
    webServerPort?: number;
  };
}

export interface ShadowsocksServer {
  // Updates the server to accept only the given access keys.
  update(keys: ShadowsocksAccessKey[]): Promise<void>;
  // Optionally updates listener-specific configuration such as WebSocket paths or ports.
  configureListeners?(listeners: ListenerSettings | undefined): void;
}
