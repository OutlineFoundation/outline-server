// Copyright 2026 The Outline Authors
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

import * as http from 'http';
import * as net from 'net';

import {requestFollowRedirectsWithSameMethodAndBody} from './follow_redirects';

describe('requestFollowRedirectsWithSameMethodAndBody', () => {
  let server: http.Server;
  let origin: string;

  beforeAll(async () => {
    server = http.createServer(async (request, response) => {
      switch (request.url) {
        case '/start':
          request.resume();
          response.writeHead(307, {Location: '/final'});
          response.end();
          return;
        case '/final':
          response.end(`${request.method}:${await readBody(request)}`);
          return;
        case '/missing':
          request.resume();
          response.writeHead(302);
          response.end();
          return;
        case '/loop':
          request.resume();
          response.writeHead(307, {Location: '/loop'});
          response.end();
          return;
        case '/timeout':
          request.resume();
          return;
        default:
          response.writeHead(404);
          response.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it('resolves relative redirects while preserving the method and body', async () => {
    const response = await requestFollowRedirectsWithSameMethodAndBody(`${origin}/start`, {
      method: 'POST',
      body: 'payload',
    });

    expect(await response.text()).toEqual('POST:payload');
  });

  it('rejects a redirect without a Location header', async () => {
    await expectAsync(
      requestFollowRedirectsWithSameMethodAndBody(`${origin}/missing`, {})
    ).toBeRejectedWithError('Redirect response is missing a Location header');
  });

  it('rejects after the redirect limit', async () => {
    await expectAsync(
      requestFollowRedirectsWithSameMethodAndBody(`${origin}/loop`, {})
    ).toBeRejectedWithError('Too many redirects');
  });

  it('honors a caller timeout while waiting for response headers', async () => {
    await expectAsync(
      requestFollowRedirectsWithSameMethodAndBody(`${origin}/timeout`, {timeout: 10})
    ).toBeRejected();
  });
});

function readBody(request: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString()));
    request.on('error', reject);
  });
}
