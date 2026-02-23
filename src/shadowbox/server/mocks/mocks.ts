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

import {PrometheusClient, QueryResultData} from '../../infrastructure/prometheus_scraper';
import {
  ListenerSettings,
  ShadowsocksAccessKey,
  ShadowsocksServer,
} from '../../model/shadowsocks_server';
import {TextFile} from '../../infrastructure/text_file';

export class InMemoryFile implements TextFile {
  private savedText: string;
  constructor(private exists: boolean) {}
  readFileSync() {
    if (this.exists) {
      return this.savedText;
    } else {
      const err = new Error('no such file or directory');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (err as any).code = 'ENOENT';
      throw err;
    }
  }
  writeFileSync(text: string) {
    this.savedText = text;
    this.exists = true;
  }
}

export class FakeShadowsocksServer implements ShadowsocksServer {
  private accessKeys: ShadowsocksAccessKey[] = [];
  private listeners?: ListenerSettings;

  update(keys: ShadowsocksAccessKey[]) {
    this.accessKeys = keys;
    return Promise.resolve();
  }

  configureListeners(listeners: ListenerSettings | undefined) {
    this.listeners = listeners;
  }

  getAccessKeys() {
    return this.accessKeys;
  }

  getListenerSettings() {
    return this.listeners;
  }
}

export class FakePrometheusClient implements PrometheusClient {
  constructor(public bytesTransferredById: {[accessKeyId: string]: number}) {}

  async query(_query: string): Promise<QueryResultData> {
    const queryResultData = {result: []} as QueryResultData;
    for (const accessKeyId of Object.keys(this.bytesTransferredById)) {
      const bytesTransferred = this.bytesTransferredById[accessKeyId] || 0;
      queryResultData.result.push({
        metric: {access_key: accessKeyId},
        value: [Date.now() / 1000, `${bytesTransferred}`],
      });
    }
    return queryResultData;
  }

  queryRange(
    _query: string,
    _start: number,
    _end: number,
    _step: string
  ): Promise<QueryResultData> {
    throw new Error('unsupported');
  }
}
