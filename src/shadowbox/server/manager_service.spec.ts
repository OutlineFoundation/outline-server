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

import fetch from 'node-fetch';
import * as net from 'net';
import * as restify from 'restify';

import {InMemoryConfig, JsonConfig} from '../infrastructure/json_config';
import {AccessKey, AccessKeyRepository, DataLimit} from '../model/access_key';
import {ManagerMetrics} from './manager_metrics';
import {bindService, ShadowsocksManagerService, convertTimeRangeToSeconds} from './manager_service';
import {FakePrometheusClient, FakeShadowsocksServer} from './mocks/mocks';
import {AccessKeyConfigJson, ServerAccessKeyRepository} from './server_access_key';
import {ServerConfigJson} from './server_config';
import {SharedMetricsPublisher} from './shared_metrics';
import {ShadowsocksServer} from '../model/shadowsocks_server';
import type {OutlineCaddyConfigPayload, OutlineCaddyController} from './outline_caddy_server';

interface ServerInfo {
  name: string;
  accessKeyDataLimit?: DataLimit;
}

const NEW_PORT = 12345;
const OLD_PORT = 54321;
const EXPECTED_ACCESS_KEY_PROPERTIES = [
  'id',
  'name',
  'password',
  'port',
  'method',
  'accessUrl',
  'dataLimit',
  'listeners',
].sort();

// Keys created directly via repo don't have listeners set
const EXPECTED_ACCESS_KEY_PROPERTIES_WITHOUT_LISTENERS = [
  'id',
  'name',
  'password',
  'port',
  'method',
  'accessUrl',
  'dataLimit',
].sort();

const SEND_NOTHING = (_httpCode, _data) => {};

describe('ShadowsocksManagerService', () => {
  // After processing the response callback, we should set
  // responseProcessed=true.  This is so we can detect that first the response
  // callback is invoked, followed by the next (done) callback.
  let responseProcessed = false;
  beforeEach(() => {
    responseProcessed = false;
  });
  afterEach(() => {
    expect(responseProcessed).toEqual(true);
  });

  describe('getServer', () => {
    it('Return default name if name is absent', () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();
      service.getServer(
        {params: {}},
        {
          send: (httpCode, data: ServerInfo) => {
            expect(httpCode).toEqual(200);
            expect(data.name).toEqual('default name');
            responseProcessed = true;
          },
        },
        () => {}
      );
    });
    it('Returns persisted properties', () => {
      const repo = getAccessKeyRepository();
      const defaultDataLimit = {bytes: 999};
      const serverConfig = new InMemoryConfig({
        name: 'Server',
        accessKeyDataLimit: defaultDataLimit,
      } as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();
      service.getServer(
        {params: {}},
        {
          send: (httpCode, data: ServerInfo) => {
            expect(httpCode).toEqual(200);
            expect(data.name).toEqual('Server');
            expect(data.accessKeyDataLimit).toEqual(defaultDataLimit);
            responseProcessed = true;
          },
        },
        () => {}
      );
    });
  });

  describe('renameServer', () => {
    it('Rename changes the server name', () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();
      service.renameServer(
        {params: {name: 'new name'}},
        {
          send: (httpCode, _) => {
            expect(httpCode).toEqual(204);
            expect(serverConfig.mostRecentWrite.name).toEqual('new name');
            responseProcessed = true;
          },
        },
        () => {}
      );
    });
  });

  describe('setHostnameForAccessKeys', () => {
    it(`accepts valid hostnames`, async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();

      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
        },
      };

      const goodHostnames = [
        '-bad',
        'localhost',
        'example.com',
        'www.example.org',
        'www.exa-mple.tw',
        '123abc.co.uk',
        '93.184.216.34',
        '::0',
        '2606:2800:220:1:248:1893:25c8:1946',
      ];
      for (const hostname of goodHostnames) {
        await service.setHostnameForAccessKeys({params: {hostname}}, res, () => {});
      }

      responseProcessed = true;
    });
    it(`rejects invalid hostnames`, async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();

      const res = {send: SEND_NOTHING};
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
      };

      const badHostnames = [
        null,
        '',
        '-abc.com',
        'abc-.com',
        'abc.com/def',
        'i_have_underscores.net',
        'gggg:ggg:220:1:248:1893:25c8:1946',
      ];
      for (const hostname of badHostnames) {
        await service.setHostnameForAccessKeys({params: {hostname}}, res, next);
      }

      responseProcessed = true;
    });
    it("Changes the server's hostname", async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();
      const hostname = 'www.example.org';
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          expect(serverConfig.data().hostname).toEqual(hostname);
          responseProcessed = true;
        },
      };
      await service.setHostnameForAccessKeys({params: {hostname}}, res, () => {});
    });
    it('Rejects missing hostname', async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();
      const res = {send: SEND_NOTHING};
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
      };
      const missingHostname = {params: {}} as {params: {hostname: string}};
      await service.setHostnameForAccessKeys(missingHostname, res, next);
    });
    it('Rejects non-string hostname', async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();
      const res = {send: SEND_NOTHING};
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const badHostname = {params: {hostname: 123}} as any as {params: {hostname: string}};
      await service.setHostnameForAccessKeys(badHostname, res, next);
    });
  });

  describe('getAccessKey', () => {
    it('Returns an access key', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key1 = await createNewAccessKeyWithName(repo, 'keyName1');
      service.getAccessKey(
        {params: {id: key1.id}},
        {
          send: (httpCode, data: AccessKey) => {
            expect(httpCode).toEqual(200);
            expect(data.id).toEqual('0');
            responseProcessed = true;
          },
        },
        () => {}
      );
    });

    it('Returns 404 if the access key does not exist', () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      service.getAccessKey({params: {id: '1'}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(404);
        responseProcessed = true;
      });
    });
  });

  describe('listAccessKeys', () => {
    it('lists access keys in order', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      // Create 2 access keys with names.
      const key1 = await createNewAccessKeyWithName(repo, 'keyName1');
      const key2 = await createNewAccessKeyWithName(repo, 'keyName2');
      // Verify that response returns keys in correct order with correct names.
      const res = {
        send: (httpCode, data) => {
          expect(httpCode).toEqual(200);
          expect(data.accessKeys.length).toEqual(2);
          expect(data.accessKeys[0].name).toEqual(key1.name);
          expect(data.accessKeys[0].id).toEqual(key1.id);
          expect(data.accessKeys[1].name).toEqual(key2.name);
          expect(data.accessKeys[1].id).toEqual(key2.id);
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      service.listAccessKeys({params: {}}, res, () => {});
    });
    it('lists access keys with expected properties', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const accessKey = await repo.createNewAccessKey();
      await repo.createNewAccessKey();
      const accessKeyName = 'new name';
      await repo.renameAccessKey(accessKey.id, accessKeyName);
      const res = {
        send: (httpCode, data) => {
          expect(httpCode).toEqual(200);
          expect(data.accessKeys.length).toEqual(2);
          const serviceAccessKey1 = data.accessKeys[0];
          const serviceAccessKey2 = data.accessKeys[1];
          expect(Object.keys(serviceAccessKey1).sort()).toEqual(
            EXPECTED_ACCESS_KEY_PROPERTIES_WITHOUT_LISTENERS
          );
          expect(Object.keys(serviceAccessKey2).sort()).toEqual(
            EXPECTED_ACCESS_KEY_PROPERTIES_WITHOUT_LISTENERS
          );
          expect(serviceAccessKey1.name).toEqual(accessKeyName);
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      service.listAccessKeys({params: {}}, res, () => {});
    });
  });

  describe('creating new access key', () => {
    let repo: ServerAccessKeyRepository;
    let service: ShadowsocksManagerService;

    beforeEach(() => {
      repo = getAccessKeyRepository();
      service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
    });

    describe('handling the access key identifier', () => {
      describe("with 'createNewAccessKey'", () => {
        it('generates a unique ID', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.id).toEqual('0');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await service.createNewAccessKey({params: {}}, res, () => {});
        });
        it('rejects requests with ID parameter set', () => {
          const res = {send: (_httpCode, _data) => {}};
          service.createNewAccessKey({params: {id: 'foobar'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
      });

      describe("with 'createAccessKey'", () => {
        it('rejects requests without ID parameter set', () => {
          const res = {send: (_httpCode, _data) => {}};
          service.createAccessKey({params: {}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('rejects non-string ID', () => {
          const res = {send: (_httpCode, _data) => {}};
          service.createAccessKey({params: {id: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('rejects if key exists', async () => {
          const accessKey = await repo.createNewAccessKey();
          const res = {send: (_httpCode, _data) => {}};
          await service.createAccessKey({params: {id: accessKey.id}}, res, (error) => {
            expect(error.statusCode).toEqual(409);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('creates key with provided ID', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.id).toEqual('myKeyId');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await service.createAccessKey({params: {id: 'myKeyId'}}, res, () => {});
        });
      });
    });

    const conditions = [
      {methodName: 'createNewAccessKey', accessKeyId: undefined},
      {methodName: 'createAccessKey', accessKeyId: 'myKeyId'},
    ];

    for (const {methodName, accessKeyId} of conditions) {
      describe(`with '${methodName}'`, () => {
        let serviceMethod: (req, res, next) => Promise<void>;

        beforeEach(() => {
          serviceMethod = service[methodName].bind(service);
        });

        it('verify default method', async () => {
          // Verify that response returns a key with the expected properties.
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(Object.keys(data).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
              expect(data.method).toEqual('chacha20-ietf-poly1305');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, () => {});
        });
        it('non-default method gets set', async () => {
          // Verify that response returns a key with the expected properties.
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(Object.keys(data).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
              expect(data.method).toEqual('aes-256-gcm');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, method: 'aes-256-gcm'}}, res, () => {});
        });
        it('use default name is params is not defined', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.name).toEqual('');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, () => {});
        });
        it('rejects non-string name', async () => {
          const res = {send: (_httpCode, _data) => {}};
          await serviceMethod({params: {id: accessKeyId, name: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('defined name is equal to stored', async () => {
          const ACCESSKEY_NAME = 'accesskeyname';
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.name).toEqual(ACCESSKEY_NAME);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, name: ACCESSKEY_NAME}}, res, () => {});
        });
        it('limit can be undefined', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.limit).toBeUndefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, () => {});
        });
        it('rejects non-numeric limits', async () => {
          const ACCESSKEY_LIMIT = {bytes: '9876'};

          const res = {send: (_httpCode, _data) => {}};
          await serviceMethod({params: {id: accessKeyId, limit: ACCESSKEY_LIMIT}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('defined limit is equal to stored', async () => {
          const ACCESSKEY_LIMIT = {bytes: 9876};
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.dataLimit).toEqual(ACCESSKEY_LIMIT);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, limit: ACCESSKEY_LIMIT}}, res, () => {});
        });
        it('method must be of type string', async () => {
          const res = {send: (_httpCode, _data) => {}};
          await serviceMethod({params: {id: accessKeyId, method: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('method must be valid', async () => {
          const res = {send: (_httpCode, _data) => {}};
          await serviceMethod({params: {id: accessKeyId, method: 'abcdef'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('Create returns a 500 when the repository throws an exception', async () => {
          spyOn(repo, 'createNewAccessKey').and.throwError('cannot write to disk');
          const res = {send: (_httpCode, _data) => {}};
          await serviceMethod({params: {id: accessKeyId, method: 'aes-192-gcm'}}, res, (error) => {
            expect(error.statusCode).toEqual(500);
            responseProcessed = true; // required for afterEach to pass.
          });
        });

        it('generates a new password when no password is provided', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.password).toBeDefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, () => {});
        });

        it('uses the provided password when one is provided', async () => {
          const PASSWORD = '8iu8V8EeoFVpwQvQeS9wiD';
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.password).toEqual(PASSWORD);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, () => {});
        });

        it('rejects a password that is not a string', async () => {
          const PASSWORD = Number.MAX_SAFE_INTEGER;
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('rejects a password that is already in use', async () => {
          const PASSWORD = 'foobar';
          await repo.createNewAccessKey({password: PASSWORD});
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, (error) => {
            expect(error.statusCode).toEqual(409);
            responseProcessed = true; // required for afterEach to pass.
          });
        });
        it('uses the default port for new keys when no port is provided', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.port).toBeDefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, () => {});
        });

        it('uses the provided port when one is provided', async () => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.port).toEqual(NEW_PORT);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, port: NEW_PORT}}, res, () => {});
        });

        it('rejects ports that are not numbers', async () => {
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, port: '1234'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });

        it('rejects invalid port numbers', async () => {
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, port: 1.4}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
          });
        });

        it('rejects port numbers already in use', async () => {
          const server = new net.Server();
          await new Promise<void>((resolve) => {
            server.listen(NEW_PORT, async () => {
              const res = {send: SEND_NOTHING};
              await serviceMethod({params: {id: accessKeyId, port: NEW_PORT}}, res, (error) => {
                expect(error.statusCode).toEqual(409);
                responseProcessed = true; // required for afterEach to pass.
                server.close();
                resolve();
              });
            });
          });
        });
      });
    }
  });
  describe('setPortForNewAccessKeys', () => {
    it('changes ports for new access keys', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      const oldKey = await repo.createNewAccessKey();
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
        },
      };
      await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, res, () => {});
      const newKey = await repo.createNewAccessKey();
      expect(newKey.proxyParams.portNumber).toEqual(NEW_PORT);
      expect(oldKey.proxyParams.portNumber).not.toEqual(NEW_PORT);
      responseProcessed = true;
    });

    it('changes the server config', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          expect(serverConfig.data().portForNewAccessKeys).toEqual(NEW_PORT);
          responseProcessed = true;
        },
      };
      await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, res, () => {});
    });

    it('rejects invalid port numbers', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      const res = {
        send: (httpCode) => {
          fail(
            `setPortForNewAccessKeys should have failed with 400 Bad Request, instead succeeded with code ${httpCode}`
          );
        },
      };
      const next = (error) => {
        // Bad Request
        expect(error.statusCode).toEqual(400);
      };

      await service.setPortForNewAccessKeys({params: {port: -1}}, res, next);
      await service.setPortForNewAccessKeys({params: {port: 0}}, res, next);
      await service.setPortForNewAccessKeys({params: {port: 100.1}}, res, next);
      await service.setPortForNewAccessKeys({params: {port: 65536}}, res, next);

      responseProcessed = true;
    });

    it('rejects port numbers already in use', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      const res = {
        send: (httpCode) => {
          fail(
            `setPortForNewAccessKeys should have failed with 409 Conflict, instead succeeded with code ${httpCode}`
          );
        },
      };
      const next = (error) => {
        // Conflict
        expect(error.statusCode).toEqual(409);
        responseProcessed = true;
      };

      const server = new net.Server();
      await new Promise<void>((resolve) => {
        server.listen(NEW_PORT, async () => {
          await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, res, next);
          server.close();
          resolve();
        });
      });
    });

    it('accepts port numbers already in use by access keys', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      await service.createNewAccessKey({params: {}}, {send: () => {}}, () => {});
      await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, {send: () => {}}, () => {});
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          responseProcessed = true;
        },
      };

      const firstKeyConnection = new net.Server();
      await new Promise<void>((resolve) => {
        firstKeyConnection.listen(OLD_PORT, async () => {
          await service.setPortForNewAccessKeys({params: {port: OLD_PORT}}, res, () => {});
          firstKeyConnection.close();
          resolve();
        });
      });
    });

    it('rejects malformed requests', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();

      const noPort = {params: {}};
      const res = {
        send: (httpCode) => {
          fail(
            `setPortForNewAccessKeys should have failed with 400 BadRequest, instead succeeded with code ${httpCode}`
          );
        },
      };
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
      };

      await service.setPortForNewAccessKeys(noPort, res, next);

      const nonNumericPort = {params: {port: 'abc'}};
      await service.setPortForNewAccessKeys(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        nonNumericPort as any as {params: {port: number}},
        res,
        next
      );

      responseProcessed = true;
    });
  });

  describe('setListeners', () => {
    it('persists configuration and updates the Shadowsocks server', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const fakeServer = new FakeShadowsocksServer();
      const fakeCaddy = new FakeOutlineCaddyServer();
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .shadowsocksServer(fakeServer)
        .caddyServer(fakeCaddy)
        .build();

      const listeners = {
        tcp: {port: 8443},
        udp: {port: 9443},
        websocketStream: {path: '/stream', webServerPort: 8080},
        websocketPacket: {path: '/packet', webServerPort: 8080},
      };

      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          responseProcessed = true;
        },
      };

      await service.setListeners({params: listeners}, res, () => {});

      expect(serverConfig.data().listeners).toEqual(listeners);
      expect(fakeServer.getListenerSettings()).toEqual({
        websocketStream: listeners.websocketStream,
        websocketPacket: listeners.websocketPacket,
      });
      expect(fakeCaddy.applyCalls.length).toEqual(1);
      expect(fakeCaddy.applyCalls[0].listeners).toEqual(listeners);
    });

    it('clears WebSocket listener settings when they are removed', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const fakeServer = new FakeShadowsocksServer();
      const fakeCaddy = new FakeOutlineCaddyServer();
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .shadowsocksServer(fakeServer)
        .caddyServer(fakeCaddy)
        .build();

      const listenersWithWebsocket = {
        tcp: {port: 8443},
        udp: {port: 8443},
        websocketStream: {path: '/tcp', webServerPort: 8080},
        websocketPacket: {path: '/udp', webServerPort: 8080},
      };
      await service.setListeners({params: listenersWithWebsocket}, {send: () => {}}, () => {});
      expect(fakeServer.getListenerSettings()).toEqual({
        websocketStream: listenersWithWebsocket.websocketStream,
        websocketPacket: listenersWithWebsocket.websocketPacket,
      });

      const listenersWithoutWebsocket = {
        tcp: {port: 9090},
        udp: {port: 9090},
      };
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          responseProcessed = true;
        },
      };
      await service.setListeners({params: listenersWithoutWebsocket}, res, () => {});

      expect(serverConfig.data().listeners).toEqual(listenersWithoutWebsocket);
      expect(fakeServer.getListenerSettings()).toBeUndefined();
      expect(fakeCaddy.applyCalls.length).toEqual(2);
      expect(fakeCaddy.applyCalls[1].listeners).toEqual(listenersWithoutWebsocket);
    });
  });

  describe('configureCaddyWebServer', () => {
    it('stores configuration and applies it', async () => {
      const repo = getAccessKeyRepository();
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const fakeCaddy = new FakeOutlineCaddyServer();
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .caddyServer(fakeCaddy)
        .build();

      const config = {
        enabled: true,
        autoHttps: true,
        email: 'admin@example.com',
        domain: 'example.com',
      };

      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          responseProcessed = true;
        },
      };

      await service.configureCaddyWebServer({params: config}, res, () => {});

      expect(serverConfig.data().caddyWebServer).toEqual(config);
      expect(fakeCaddy.applyCalls.length).toEqual(1);
      expect(fakeCaddy.applyCalls[0].caddyConfig).toEqual(config);
    });
  });

  describe('removeAccessKey', () => {
    it('removes keys', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key1 = await repo.createNewAccessKey();
      const key2 = await repo.createNewAccessKey();
      const res = {
        send: (httpCode, _data) => {
          expect(httpCode).toEqual(204);
          // expect that the only remaining key is the 2nd key we created.
          const keys = repo.listAccessKeys();
          expect(keys.length).toEqual(1);
          expect(keys[0].id === key2.id);
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      // remove the 1st key.
      await service.removeAccessKey({params: {id: key1.id}}, res, () => {});
    });
    it('Remove returns a 500 when the repository throws an exception', async () => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'removeAccessKey').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key = await createNewAccessKeyWithName(repo, 'keyName1');
      const res = {send: (_httpCode, _data) => {}};
      service.removeAccessKey({params: {id: key.id}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
  });

  describe('renameAccessKey', () => {
    it('renames keys', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const OLD_NAME = 'oldName';
      const NEW_NAME = 'newName';

      const key = await createNewAccessKeyWithName(repo, OLD_NAME);
      expect(key.name === OLD_NAME);
      const res = {
        send: (httpCode, _) => {
          expect(httpCode).toEqual(204);
          expect(key.name === NEW_NAME);
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      service.renameAccessKey({params: {id: key.id, name: NEW_NAME}}, res, () => {});
    });
    it('Rename returns a 400 when the access key id is not a string', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();

      await repo.createNewAccessKey();
      const res = {send: SEND_NOTHING};
      service.renameAccessKey({params: {id: 123}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
    it('Rename returns a 500 when the repository throws an exception', async () => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'renameAccessKey').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();

      const key = await createNewAccessKeyWithName(repo, 'oldName');
      const res = {send: SEND_NOTHING};
      service.renameAccessKey({params: {id: key.id, name: 'newName'}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
  });

  describe('setAccessKeyDataLimit', () => {
    it('sets access key data limit', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key = await repo.createNewAccessKey();
      const limit = {bytes: 1000};
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          expect(key.dataLimit.bytes).toEqual(1000);
          responseProcessed = true;
        },
      };
      service.setAccessKeyDataLimit({params: {id: key.id, limit}}, res, () => {});
    });

    it('rejects negative numbers', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {bytes: -1};
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
      });
    });

    it('rejects non-numeric limits', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {bytes: '1'};
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
      });
    });

    it('rejects an empty request', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {} as DataLimit;
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
      });
    });

    it('rejects requests for nonexistent keys', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit: DataLimit = {bytes: 1000};
      service.setAccessKeyDataLimit(
        {params: {id: 'not an id', limit}},
        {send: () => {}},
        (error) => {
          expect(error.statusCode).toEqual(404);
          responseProcessed = true;
        }
      );
    });
  });

  describe('removeAccessKeyDataLimit', () => {
    it('removes an access key data limit', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key = await repo.createNewAccessKey();
      repo.setAccessKeyDataLimit(key.id, {bytes: 1000});
      await repo.enforceAccessKeyDataLimits();
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          expect(key.dataLimit).toBeFalsy();
          responseProcessed = true;
        },
      };
      service.removeAccessKeyDataLimit({params: {id: key.id}}, res, () => {});
    });
    it('returns 404 for a nonexistent key', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      service.removeAccessKeyDataLimit({params: {id: 'not an id'}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(404);
        responseProcessed = true;
      });
    });
  });

  describe('setDefaultDataLimit', () => {
    it('sets default data limit', async () => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const repo = getAccessKeyRepository();
      spyOn(repo, 'setDefaultDataLimit');
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();
      const limit = {bytes: 10000};
      const res = {
        send: (httpCode, _data) => {
          expect(httpCode).toEqual(204);
          expect(serverConfig.data().accessKeyDataLimit).toEqual(limit);
          expect(repo.setDefaultDataLimit).toHaveBeenCalledWith(limit);
          service.getServer(
            {params: {}},
            {
              send: (httpCode, data: ServerInfo) => {
                expect(httpCode).toEqual(200);
                expect(data.accessKeyDataLimit).toEqual(limit);
                responseProcessed = true; // required for afterEach to pass.
              },
            },
            () => {}
          );
        },
      };
      service.setDefaultDataLimit({params: {limit}}, res, () => {});
    });
    it('returns 400 when limit is missing values', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {} as DataLimit;
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
    it('returns 400 when limit has negative values', async () => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {bytes: -1};
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
    it('returns 500 when the repository throws an exception', async () => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'setDefaultDataLimit').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {bytes: 10000};
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
  });

  describe('removeDefaultDataLimit', () => {
    it('clears default data limit', async () => {
      const limit = {bytes: 10000};
      const serverConfig = new InMemoryConfig({accessKeyDataLimit: limit} as ServerConfigJson);
      const repo = getAccessKeyRepository();
      spyOn(repo, 'removeDefaultDataLimit').and.callThrough();
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(repo)
        .build();
      await repo.setDefaultDataLimit(limit);
      const res = {
        send: (httpCode, _data) => {
          expect(httpCode).toEqual(204);
          expect(serverConfig.data().accessKeyDataLimit).toBeUndefined();
          expect(repo.removeDefaultDataLimit).toHaveBeenCalled();
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      service.removeDefaultDataLimit({params: {}}, res, () => {});
    });
    it('returns 500 when the repository throws an exception', async () => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'removeDefaultDataLimit').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const accessKey = await repo.createNewAccessKey();
      const res = {send: SEND_NOTHING};
      service.removeDefaultDataLimit({params: {id: accessKey.id}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
      });
    });
  });

  describe('getShareMetrics', () => {
    it('Returns value from sharedMetrics', () => {
      const sharedMetrics = fakeSharedMetricsReporter();
      sharedMetrics.startSharing();
      const service = new ShadowsocksManagerServiceBuilder()
        .metricsPublisher(sharedMetrics)
        .build();
      service.getShareMetrics(
        {params: {}},
        {
          send: (httpCode, data: {metricsEnabled: boolean}) => {
            expect(httpCode).toEqual(200);
            expect(data.metricsEnabled).toEqual(true);
            responseProcessed = true;
          },
        },
        () => {}
      );
    });
  });
  describe('setShareMetrics', () => {
    it('Sets value in the config', () => {
      const sharedMetrics = fakeSharedMetricsReporter();
      sharedMetrics.stopSharing();
      const service = new ShadowsocksManagerServiceBuilder()
        .metricsPublisher(sharedMetrics)
        .build();
      service.setShareMetrics(
        {params: {metricsEnabled: true}},
        {
          send: (httpCode, _) => {
            expect(httpCode).toEqual(204);
            expect(sharedMetrics.isSharingEnabled()).toEqual(true);
            responseProcessed = true;
          },
        },
        () => {}
      );
    });
  });
});

describe('bindService', () => {
  let server: restify.Server;
  let service: ShadowsocksManagerService;
  let url: URL;
  const PREFIX = '/TestApiPrefix';

  const fakeResponse = {foo: 'bar'};
  const fakeHandler = async (req, res, next) => {
    res.send(200, fakeResponse);
    next();
  };

  beforeEach(() => {
    server = restify.createServer();
    service = new ShadowsocksManagerServiceBuilder().build();
    server.listen(0);
    url = new URL(server.url);
  });

  afterEach(() => {
    server.close();
  });

  it('basic routing', async () => {
    spyOn(service, 'renameServer').and.callFake(fakeHandler);
    bindService(server, PREFIX, service);

    url.pathname = `${PREFIX}/name`;
    const response = await fetch(url, {method: 'put'});
    const body = await response.json();

    expect(body).toEqual(fakeResponse);
    expect(service.renameServer).toHaveBeenCalled();
  });

  it('parameterized routing', async () => {
    spyOn(service, 'removeAccessKeyDataLimit').and.callFake(fakeHandler);
    bindService(server, PREFIX, service);

    url.pathname = `${PREFIX}/access-keys/fake-access-key-id/data-limit`;
    const response = await fetch(url, {method: 'delete'});
    const body = await response.json();

    expect(body).toEqual(fakeResponse);
    expect(service.removeAccessKeyDataLimit).toHaveBeenCalled();
  });

  // Verify that we have consistent 404 behavior for all inputs.
  [
    '/',
    '/TestApiPre',
    '/foo',
    '/TestApiPrefix123',
    '/123TestApiPrefix',
    '/very-long-path-that-does-not-exist',
    `${PREFIX}/does-not-exist`,
  ].forEach((path) => {
    it(`404 (${path})`, async () => {
      // Ensure no methods are called on the Service.
      spyOnAllFunctions(service);
      jasmine.setDefaultSpyStrategy(fail);
      bindService(server, PREFIX, service);

      url.pathname = path;
      const response = await fetch(url);
      const body = await response.json();

      expect(response.status).toEqual(404);
      expect(body).toEqual({
        code: 'ResourceNotFound',
        message: `${path} does not exist`,
      });
    });
  });

  // This is primarily a reverse testcase for the unauthorized case.
  it(`standard routing for authorized queries`, async () => {
    bindService(server, PREFIX, service);
    // Verify that ordinary routing goes through the Router.
    spyOn(server.router, 'lookup').and.callThrough();

    // This is an authorized request, so it will pass the prefix filter
    // and reach the Router.
    url.pathname = `${PREFIX}`;
    const response = await fetch(url);
    expect(response.status).toEqual(404);
    await response.json();

    expect(server.router.lookup).toHaveBeenCalled();
  });

  // Check that unauthorized queries are rejected without ever reaching
  // the routing stage.
  ['/', '/T', '/TestApiPre', '/TestApi123456', '/TestApi123456789'].forEach((path) => {
    it(`no routing for unauthorized queries (${path})`, async () => {
      bindService(server, PREFIX, service);
      // Ensure no methods are called on the Router.
      spyOnAllFunctions(server.router);
      jasmine.setDefaultSpyStrategy(fail);

      // Try bare pathname.
      url.pathname = path;
      const response1 = await fetch(url);
      expect(response1.status).toEqual(404);
      await response1.json();

      // Try a subpath that would exist if this were a valid prefix
      url.pathname = `${path}/server`;
      const response2 = await fetch(url);
      expect(response2.status).toEqual(404);
      await response2.json();

      // Try an arbitrary subpath
      url.pathname = `${path}/does-not-exist`;
      const response3 = await fetch(url);
      expect(response3.status).toEqual(404);
      await response3.json();
    });
  });
});

describe('convertTimeRangeToHours', () => {
  it('properly parses time ranges', () => {
    expect(convertTimeRangeToSeconds('30d')).toEqual(30 * 24 * 60 * 60);
    expect(convertTimeRangeToSeconds('20h')).toEqual(20 * 60 * 60);
    expect(convertTimeRangeToSeconds('3w')).toEqual(7 * 3 * 24 * 60 * 60);
  });

  it('throws when an invalid time range is provided', () => {
    expect(() => convertTimeRangeToSeconds('30dd')).toThrow();
    expect(() => convertTimeRangeToSeconds('hi mom')).toThrow();
    expect(() => convertTimeRangeToSeconds('1j')).toThrow();
  });
});

class FakeOutlineCaddyServer implements OutlineCaddyController {
  applyCalls: OutlineCaddyConfigPayload[] = [];
  shouldFail = false;

  async applyConfig(payload: OutlineCaddyConfigPayload): Promise<void> {
    this.applyCalls.push(payload);
    if (this.shouldFail) {
      throw new Error('applyConfig failure');
    }
  }

  async stop(): Promise<void> {
    return Promise.resolve();
  }
}

class ShadowsocksManagerServiceBuilder {
  private defaultServerName_ = 'default name';
  private serverConfig_: JsonConfig<ServerConfigJson> = new InMemoryConfig<ServerConfigJson>(
    {} as ServerConfigJson
  );
  private accessKeys_: AccessKeyRepository = null;
  private shadowsocksServer_: ShadowsocksServer = null;
  private managerMetrics_: ManagerMetrics = null;
  private metricsPublisher_: SharedMetricsPublisher = null;
  private caddyServer_: OutlineCaddyController = new FakeOutlineCaddyServer();

  defaultServerName(name: string): ShadowsocksManagerServiceBuilder {
    this.defaultServerName_ = name;
    return this;
  }

  serverConfig(config: JsonConfig<ServerConfigJson>): ShadowsocksManagerServiceBuilder {
    this.serverConfig_ = config;
    return this;
  }

  accessKeys(keys: AccessKeyRepository): ShadowsocksManagerServiceBuilder {
    this.accessKeys_ = keys;
    return this;
  }

  shadowsocksServer(server: ShadowsocksServer) {
    this.shadowsocksServer_ = server;
    return this;
  }

  managerMetrics(metrics: ManagerMetrics): ShadowsocksManagerServiceBuilder {
    this.managerMetrics_ = metrics;
    return this;
  }

  metricsPublisher(publisher: SharedMetricsPublisher): ShadowsocksManagerServiceBuilder {
    this.metricsPublisher_ = publisher;
    return this;
  }

  caddyServer(server: OutlineCaddyController): ShadowsocksManagerServiceBuilder {
    this.caddyServer_ = server;
    return this;
  }

  build(): ShadowsocksManagerService {
    return new ShadowsocksManagerService(
      this.defaultServerName_,
      this.serverConfig_,
      this.accessKeys_,
      this.shadowsocksServer_,
      this.managerMetrics_,
      this.metricsPublisher_,
      this.caddyServer_
    );
  }
}

async function createNewAccessKeyWithName(
  repo: AccessKeyRepository,
  name: string
): Promise<AccessKey> {
  const accessKey = await repo.createNewAccessKey();
  try {
    repo.renameAccessKey(accessKey.id, name);
  } catch (e) {
    // Ignore; writing to disk is expected to fail in some of the tests.
  }
  return accessKey;
}

function fakeSharedMetricsReporter(): SharedMetricsPublisher {
  let sharing = false;
  return {
    startSharing() {
      sharing = true;
    },
    stopSharing() {
      sharing = false;
    },
    isSharingEnabled(): boolean {
      return sharing;
    },
  };
}

function getAccessKeyRepository(): ServerAccessKeyRepository {
  return new ServerAccessKeyRepository(
    OLD_PORT,
    'hostname',
    new InMemoryConfig<AccessKeyConfigJson>({accessKeys: [], nextId: 0}),
    new FakeShadowsocksServer(),
    new FakePrometheusClient({})
  );
}
