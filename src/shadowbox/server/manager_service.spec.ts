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
    it('Return default name if name is absent', (done) => {
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
        done
      );
    });
    it('Returns persisted properties', (done) => {
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
        done
      );
    });
  });

  describe('renameServer', () => {
    it('Rename changes the server name', (done) => {
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
        done
      );
    });
  });

  describe('setHostnameForAccessKeys', () => {
    it(`accepts valid hostnames`, (done) => {
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
        service.setHostnameForAccessKeys({params: {hostname}}, res, () => {});
      }

      responseProcessed = true;
      done();
    });
    it(`rejects invalid hostnames`, (done) => {
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
        service.setHostnameForAccessKeys({params: {hostname}}, res, next);
      }

      responseProcessed = true;
      done();
    });
    it("Changes the server's hostname", (done) => {
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
      service.setHostnameForAccessKeys({params: {hostname}}, res, done);
    });
    it('Rejects missing hostname', (done) => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();
      const res = {send: SEND_NOTHING};
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
        done();
      };
      const missingHostname = {params: {}} as {params: {hostname: string}};
      service.setHostnameForAccessKeys(missingHostname, res, next);
    });
    it('Rejects non-string hostname', (done) => {
      const serverConfig = new InMemoryConfig({} as ServerConfigJson);
      const service = new ShadowsocksManagerServiceBuilder()
        .serverConfig(serverConfig)
        .accessKeys(getAccessKeyRepository())
        .build();
      const res = {send: SEND_NOTHING};
      const next = (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
        done();
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const badHostname = {params: {hostname: 123}} as any as {params: {hostname: string}};
      service.setHostnameForAccessKeys(badHostname, res, next);
    });
  });

  describe('getAccessKey', () => {
    it('Returns an access key', async (done) => {
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
        done
      );
    });

    it('Returns 404 if the access key does not exist', (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      service.getAccessKey({params: {id: '1'}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(404);
        responseProcessed = true;
        done();
      });
    });
  });

  describe('listAccessKeys', () => {
    it('lists access keys in order', async (done) => {
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
      service.listAccessKeys({params: {}}, res, done);
    });
    it('lists access keys with expected properties', async (done) => {
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
          expect(Object.keys(serviceAccessKey1).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
          expect(Object.keys(serviceAccessKey2).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
          expect(serviceAccessKey1.name).toEqual(accessKeyName);
          responseProcessed = true; // required for afterEach to pass.
        },
      };
      service.listAccessKeys({params: {}}, res, done);
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
        it('generates a unique ID', (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.id).toEqual('0');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          service.createNewAccessKey({params: {}}, res, done);
        });
        it('rejects requests with ID parameter set', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          service.createNewAccessKey({params: {id: 'foobar'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
      });

      describe("with 'createAccessKey'", () => {
        it('rejects requests without ID parameter set', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          service.createAccessKey({params: {}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('rejects non-string ID', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          service.createAccessKey({params: {id: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('rejects if key exists', async (done) => {
          const accessKey = await repo.createNewAccessKey();
          const res = {send: (_httpCode, _data) => {}};
          service.createAccessKey({params: {id: accessKey.id}}, res, (error) => {
            expect(error.statusCode).toEqual(409);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('creates key with provided ID', (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.id).toEqual('myKeyId');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          service.createAccessKey({params: {id: 'myKeyId'}}, res, done);
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

        it('verify default method', (done) => {
          // Verify that response returns a key with the expected properties.
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(Object.keys(data).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
              expect(data.method).toEqual('chacha20-ietf-poly1305');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId}}, res, done);
        });
        it('non-default method gets set', (done) => {
          // Verify that response returns a key with the expected properties.
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(Object.keys(data).sort()).toEqual(EXPECTED_ACCESS_KEY_PROPERTIES);
              expect(data.method).toEqual('aes-256-gcm');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId, method: 'aes-256-gcm'}}, res, done);
        });
        it('use default name is params is not defined', (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.name).toEqual('');
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId}}, res, done);
        });
        it('rejects non-string name', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          serviceMethod({params: {id: accessKeyId, name: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('defined name is equal to stored', (done) => {
          const ACCESSKEY_NAME = 'accesskeyname';
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.name).toEqual(ACCESSKEY_NAME);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId, name: ACCESSKEY_NAME}}, res, done);
        });
        it('limit can be undefined', (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.limit).toBeUndefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId}}, res, done);
        });
        it('rejects non-numeric limits', (done) => {
          const ACCESSKEY_LIMIT = {bytes: '9876'};

          const res = {send: (_httpCode, _data) => {}};
          serviceMethod({params: {id: accessKeyId, limit: ACCESSKEY_LIMIT}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('defined limit is equal to stored', (done) => {
          const ACCESSKEY_LIMIT = {bytes: 9876};
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.dataLimit).toEqual(ACCESSKEY_LIMIT);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          serviceMethod({params: {id: accessKeyId, limit: ACCESSKEY_LIMIT}}, res, done);
        });
        it('method must be of type string', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          serviceMethod({params: {id: accessKeyId, method: Number('9876')}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('method must be valid', (done) => {
          const res = {send: (_httpCode, _data) => {}};
          serviceMethod({params: {id: accessKeyId, method: 'abcdef'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('Create returns a 500 when the repository throws an exception', (done) => {
          spyOn(repo, 'createNewAccessKey').and.throwError('cannot write to disk');
          const res = {send: (_httpCode, _data) => {}};
          serviceMethod({params: {id: accessKeyId, method: 'aes-192-gcm'}}, res, (error) => {
            expect(error.statusCode).toEqual(500);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });

        it('generates a new password when no password is provided', async (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.password).toBeDefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, done);
        });

        it('uses the provided password when one is provided', async (done) => {
          const PASSWORD = '8iu8V8EeoFVpwQvQeS9wiD';
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.password).toEqual(PASSWORD);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, done);
        });

        it('rejects a password that is not a string', async (done) => {
          const PASSWORD = Number.MAX_SAFE_INTEGER;
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('rejects a password that is already in use', async (done) => {
          const PASSWORD = 'foobar';
          await repo.createNewAccessKey({password: PASSWORD});
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, password: PASSWORD}}, res, (error) => {
            expect(error.statusCode).toEqual(409);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });
        it('uses the default port for new keys when no port is provided', async (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.port).toBeDefined();
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId}}, res, done);
        });

        it('uses the provided port when one is provided', async (done) => {
          const res = {
            send: (httpCode, data) => {
              expect(httpCode).toEqual(201);
              expect(data.port).toEqual(NEW_PORT);
              responseProcessed = true; // required for afterEach to pass.
            },
          };
          await serviceMethod({params: {id: accessKeyId, port: NEW_PORT}}, res, done);
        });

        it('rejects ports that are not numbers', async (done) => {
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, port: '1234'}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });

        it('rejects invalid port numbers', async (done) => {
          const res = {send: SEND_NOTHING};
          await serviceMethod({params: {id: accessKeyId, port: 1.4}}, res, (error) => {
            expect(error.statusCode).toEqual(400);
            responseProcessed = true; // required for afterEach to pass.
            done();
          });
        });

        it('rejects port numbers already in use', async (done) => {
          const server = new net.Server();
          server.listen(NEW_PORT, async () => {
            const res = {send: SEND_NOTHING};
            await serviceMethod({params: {id: accessKeyId, port: NEW_PORT}}, res, (error) => {
              expect(error.statusCode).toEqual(409);
              responseProcessed = true; // required for afterEach to pass.
              server.close();
              done();
            });
          });
        });
      });
    }
  });
  describe('setPortForNewAccessKeys', () => {
    it('changes ports for new access keys', async (done) => {
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
      done();
    });

    it('changes the server config', async (done) => {
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
      await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, res, done);
    });

    it('rejects invalid port numbers', async (done) => {
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
      done();
    });

    it('rejects port numbers already in use', async (done) => {
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
        done();
      };

      const server = new net.Server();
      server.listen(NEW_PORT, async () => {
        await service.setPortForNewAccessKeys({params: {port: NEW_PORT}}, res, next);
        server.close();
      });
    });

    it('accepts port numbers already in use by access keys', async (done) => {
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
      firstKeyConnection.listen(OLD_PORT, async () => {
        await service.setPortForNewAccessKeys({params: {port: OLD_PORT}}, res, () => {});
        firstKeyConnection.close();
        done();
      });
    });

    it('rejects malformed requests', async (done) => {
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
      done();
    });
  });

  describe('removeAccessKey', () => {
    it('removes keys', async (done) => {
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
      service.removeAccessKey({params: {id: key1.id}}, res, done);
    });
    it('Remove returns a 500 when the repository throws an exception', async (done) => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'removeAccessKey').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key = await createNewAccessKeyWithName(repo, 'keyName1');
      const res = {send: (_httpCode, _data) => {}};
      service.removeAccessKey({params: {id: key.id}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
  });

  describe('renameAccessKey', () => {
    it('renames keys', async (done) => {
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
      service.renameAccessKey({params: {id: key.id, name: NEW_NAME}}, res, done);
    });
    it('Rename returns a 400 when the access key id is not a string', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();

      await repo.createNewAccessKey();
      const res = {send: SEND_NOTHING};
      service.renameAccessKey({params: {id: 123}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
    it('Rename returns a 500 when the repository throws an exception', async (done) => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'renameAccessKey').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();

      const key = await createNewAccessKeyWithName(repo, 'oldName');
      const res = {send: SEND_NOTHING};
      service.renameAccessKey({params: {id: key.id, name: 'newName'}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
  });

  describe('setAccessKeyDataLimit', () => {
    it('sets access key data limit', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const key = await repo.createNewAccessKey();
      const limit = {bytes: 1000};
      const res = {
        send: (httpCode) => {
          expect(httpCode).toEqual(204);
          expect(key.dataLimit.bytes).toEqual(1000);
          responseProcessed = true;
          done();
        },
      };
      service.setAccessKeyDataLimit({params: {id: key.id, limit}}, res, () => {});
    });

    it('rejects negative numbers', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {bytes: -1};
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
        done();
      });
    });

    it('rejects non-numeric limits', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {bytes: '1'};
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
        done();
      });
    });

    it('rejects an empty request', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const keyId = (await repo.createNewAccessKey()).id;
      const limit = {} as DataLimit;
      service.setAccessKeyDataLimit({params: {id: keyId, limit}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true;
        done();
      });
    });

    it('rejects requests for nonexistent keys', async (done) => {
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
          done();
        }
      );
    });
  });

  describe('removeAccessKeyDataLimit', () => {
    it('removes an access key data limit', async (done) => {
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
          done();
        },
      };
      service.removeAccessKeyDataLimit({params: {id: key.id}}, res, () => {});
    });
    it('returns 404 for a nonexistent key', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      service.removeAccessKeyDataLimit({params: {id: 'not an id'}}, {send: () => {}}, (error) => {
        expect(error.statusCode).toEqual(404);
        responseProcessed = true;
        done();
      });
    });
  });

  describe('setDefaultDataLimit', () => {
    it('sets default data limit', async (done) => {
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
            done
          );
        },
      };
      service.setDefaultDataLimit({params: {limit}}, res, done);
    });
    it('returns 400 when limit is missing values', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {} as DataLimit;
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
    it('returns 400 when limit has negative values', async (done) => {
      const repo = getAccessKeyRepository();
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {bytes: -1};
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
    it('returns 500 when the repository throws an exception', async (done) => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'setDefaultDataLimit').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      await repo.createNewAccessKey();
      const limit = {bytes: 10000};
      const res = {send: SEND_NOTHING};
      service.setDefaultDataLimit({params: {limit}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
  });

  describe('removeDefaultDataLimit', () => {
    it('clears default data limit', async (done) => {
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
      service.removeDefaultDataLimit({params: {}}, res, done);
    });
    it('returns 500 when the repository throws an exception', async (done) => {
      const repo = getAccessKeyRepository();
      spyOn(repo, 'removeDefaultDataLimit').and.throwError('cannot write to disk');
      const service = new ShadowsocksManagerServiceBuilder().accessKeys(repo).build();
      const accessKey = await repo.createNewAccessKey();
      const res = {send: SEND_NOTHING};
      service.removeDefaultDataLimit({params: {id: accessKey.id}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true; // required for afterEach to pass.
        done();
      });
    });
  });

  describe('getDataUsage', () => {
    it('Uses default 30-day timeframe when no last parameter provided', async (done) => {
      const mockMetrics = jasmine.createSpyObj<ManagerMetrics>('ManagerMetrics', [
        'getOutboundByteTransfer',
      ]);
      const expectedResponse = {bytesTransferredByUserId: {key1: 1000, key2: 2000}};
      mockMetrics.getOutboundByteTransfer.and.returnValue(Promise.resolve(expectedResponse));

      const service = new ShadowsocksManagerServiceBuilder().managerMetrics(mockMetrics).build();

      service.getDataUsage(
        {params: {}, query: {}},
        {
          send: (httpCode, data) => {
            expect(httpCode).toEqual(200);
            expect(data).toEqual(expectedResponse);
            // Expect default 30 days = 30 * 24 = 720 hours
            expect(mockMetrics.getOutboundByteTransfer).toHaveBeenCalledWith({hours: 720});
            responseProcessed = true;
          },
        },
        done
      );
    });

    it('Uses provided last parameter correctly', async (done) => {
      const mockMetrics = jasmine.createSpyObj<ManagerMetrics>('ManagerMetrics', [
        'getOutboundByteTransfer',
      ]);
      const expectedResponse = {bytesTransferredByUserId: {key1: 1500}};
      mockMetrics.getOutboundByteTransfer.and.returnValue(Promise.resolve(expectedResponse));

      const service = new ShadowsocksManagerServiceBuilder().managerMetrics(mockMetrics).build();

      service.getDataUsage(
        {params: {}, query: {last: '2d'}}, // 2 days = 48 hours
        {
          send: (httpCode, data) => {
            expect(httpCode).toEqual(200);
            expect(data).toEqual(expectedResponse);
            expect(mockMetrics.getOutboundByteTransfer).toHaveBeenCalledWith({hours: 48});
            responseProcessed = true;
          },
        },
        done
      );
    });

    it('Handles hours format correctly', async (done) => {
      const mockMetrics = jasmine.createSpyObj<ManagerMetrics>('ManagerMetrics', [
        'getOutboundByteTransfer',
      ]);
      const expectedResponse = {bytesTransferredByUserId: {key1: 3000}};
      mockMetrics.getOutboundByteTransfer.and.returnValue(Promise.resolve(expectedResponse));

      const service = new ShadowsocksManagerServiceBuilder().managerMetrics(mockMetrics).build();

      service.getDataUsage(
        {params: {}, query: {last: '24h'}}, // 24 hours
        {
          send: (httpCode, data) => {
            expect(httpCode).toEqual(200);
            expect(data).toEqual(expectedResponse);
            expect(mockMetrics.getOutboundByteTransfer).toHaveBeenCalledWith({hours: 24});
            responseProcessed = true;
          },
        },
        done
      );
    });

    it('Rejects negative last parameter', async (done) => {
      const service = new ShadowsocksManagerServiceBuilder().build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: '-12h'}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        expect(error.message).toContain('Invalid time range');
        responseProcessed = true;
        done();
      });
    });

    it('Rejects zero last parameter', async (done) => {
      const service = new ShadowsocksManagerServiceBuilder().build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: '0h'}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        expect(error.message).toContain('Invalid time range');
        responseProcessed = true;
        done();
      });
    });

    it('Rejects invalid string last parameter', async (done) => {
      const service = new ShadowsocksManagerServiceBuilder().build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: 'invalid'}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        expect(error.message).toContain('Invalid time range');
        responseProcessed = true;
        done();
      });
    });

    it('Rejects non-string last parameter', async (done) => {
      const service = new ShadowsocksManagerServiceBuilder().build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: {invalid: 'object'}}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        expect(error.message).toContain('Parameter `last` must be a string');
        responseProcessed = true;
        done();
      });
    });

    it('Handles weeks format correctly', async (done) => {
      const mockMetrics = jasmine.createSpyObj<ManagerMetrics>('ManagerMetrics', [
        'getOutboundByteTransfer',
      ]);
      const expectedResponse = {bytesTransferredByUserId: {key1: 5000}};
      mockMetrics.getOutboundByteTransfer.and.returnValue(Promise.resolve(expectedResponse));

      const service = new ShadowsocksManagerServiceBuilder().managerMetrics(mockMetrics).build();

      service.getDataUsage(
        {params: {}, query: {last: '2w'}}, // 2 weeks = 14 days = 336 hours
        {
          send: (httpCode, data) => {
            expect(httpCode).toEqual(200);
            expect(data).toEqual(expectedResponse);
            expect(mockMetrics.getOutboundByteTransfer).toHaveBeenCalledWith({hours: 336});
            responseProcessed = true;
          },
        },
        done
      );
    });

    it('Rejects invalid time unit', async (done) => {
      const service = new ShadowsocksManagerServiceBuilder().build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: '30s'}}, res, (error) => {
        expect(error.statusCode).toEqual(400);
        expect(error.message).toContain('Invalid time range');
        responseProcessed = true;
        done();
      });
    });

    it('Handles manager metrics error properly', async (done) => {
      const mockMetrics = jasmine.createSpyObj<ManagerMetrics>('ManagerMetrics', [
        'getOutboundByteTransfer',
      ]);
      mockMetrics.getOutboundByteTransfer.and.returnValue(
        Promise.reject(new Error('Prometheus error'))
      );

      const service = new ShadowsocksManagerServiceBuilder().managerMetrics(mockMetrics).build();
      const res = {send: SEND_NOTHING};

      service.getDataUsage({params: {}, query: {last: '24h'}}, res, (error) => {
        expect(error.statusCode).toEqual(500);
        responseProcessed = true;
        done();
      });
    });
  });

  describe('getShareMetrics', () => {
    it('Returns value from sharedMetrics', (done) => {
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
        done
      );
    });
  });
  describe('setShareMetrics', () => {
    it('Sets value in the config', (done) => {
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
        done
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

  it('throws when zero or negative values are provided', () => {
    expect(() => convertTimeRangeToSeconds('0h')).toThrow();
    expect(() => convertTimeRangeToSeconds('-5d')).toThrow();
  });
});

class ShadowsocksManagerServiceBuilder {
  private defaultServerName_ = 'default name';
  private serverConfig_: JsonConfig<ServerConfigJson> = null;
  private accessKeys_: AccessKeyRepository = null;
  private shadowsocksServer_: ShadowsocksServer = null;
  private managerMetrics_: ManagerMetrics = null;
  private metricsPublisher_: SharedMetricsPublisher = null;

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

  build(): ShadowsocksManagerService {
    return new ShadowsocksManagerService(
      this.defaultServerName_,
      this.serverConfig_,
      this.accessKeys_,
      this.shadowsocksServer_,
      this.managerMetrics_,
      this.metricsPublisher_
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
