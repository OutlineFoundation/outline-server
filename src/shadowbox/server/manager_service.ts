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

import * as crypto from 'crypto';
import * as ipRegex from 'ip-regex';
import * as restify from 'restify';
import * as restifyErrors from 'restify-errors';
import {makeConfig, SIP002_URI} from 'outline-shadowsocksconfig';

import {JsonConfig} from '../infrastructure/json_config';
import * as logging from '../infrastructure/logging';
import {AccessKey, AccessKeyRepository, DataLimit, ListenerType} from '../model/access_key';
import * as errors from '../model/errors';
import * as version from './version';

import {ManagerMetrics} from './manager_metrics';
import {ServerConfigJson, ListenersConfig, WebServerConfig} from './server_config';
import {SharedMetricsPublisher} from './shared_metrics';
import {ShadowsocksServer} from '../model/shadowsocks_server';
import type {OutlineCaddyController} from './outline_caddy_server';

interface AccessKeyJson {
  // The unique identifier of this access key.
  id: string;
  // Admin-controlled, editable name for this access key.
  name: string;
  // Shadowsocks-specific details and credentials.
  // These fields are only present when the key has TCP or UDP listeners.
  // For WSS-only keys, this information is in dynamicConfig instead.
  password?: string;
  port?: number;
  method?: string;
  dataLimit?: DataLimit;
  accessUrl?: string;
  listeners?: ListenerType[];
  // For WebSocket-enabled keys, the dynamic access configuration as a JSON object.
  // This can be converted to YAML and hosted on a censorship-resistant platform.
  // Compatible with Outline Client v1.15.0+.
  dynamicConfig?: Record<string, unknown>;
}

// Type to reflect that we receive untyped JSON request parameters.
interface RequestParams {
  // Supported parameters:
  //   id: string
  //   name: string
  //   metricsEnabled: boolean
  //   limit: DataLimit
  //   port: number
  //   hours: number
  //   method: string
  [param: string]: unknown;
}

// Type to reflect that we recive an untyped query string
interface RequestQuery {
  // Supported parameters:
  //  since: string
  [param: string]: unknown;
}

// Simplified request and response type interfaces containing only the
// properties we actually use, to make testing easier.
interface RequestType {
  params: RequestParams;
  query?: RequestQuery;
}
interface ResponseType {
  send(code: number, data?: {}): void;
}

enum HttpSuccess {
  OK = 200,
  NO_CONTENT = 204,
}

// Similar to String.startsWith(), but constant-time.
function timingSafeStartsWith(input: string, prefix: string): boolean {
  const prefixBuf = Buffer.from(prefix);
  const inputBuf = Buffer.from(input);
  const L = Math.min(inputBuf.length, prefixBuf.length);
  const inputOverlap = inputBuf.slice(0, L);
  const prefixOverlap = prefixBuf.slice(0, L);
  const match = crypto.timingSafeEqual(inputOverlap, prefixOverlap);
  return inputBuf.length >= prefixBuf.length && match;
}

// Returns a pre-routing hook that injects a 404 if the request does not
// start with `apiPrefix`.  This filter runs in constant time.
function prefixFilter(apiPrefix: string): restify.RequestHandler {
  return (req: restify.Request, res: restify.Response, next: restify.Next) => {
    if (timingSafeStartsWith(req.path(), apiPrefix)) {
      return next();
    }
    // This error matches the router's default 404 response.
    next(new restifyErrors.ResourceNotFoundError('%s does not exist', req.path()));
  };
}

export function bindService(
  apiServer: restify.Server,
  apiPrefix: string,
  service: ShadowsocksManagerService
) {
  // Reject unauthorized requests in constant time before they reach the routing step.
  apiServer.pre(prefixFilter(apiPrefix));

  apiServer.put(`${apiPrefix}/name`, service.renameServer.bind(service));
  apiServer.get(`${apiPrefix}/server`, service.getServer.bind(service));
  apiServer.get(`${apiPrefix}/experimental/server/metrics`, service.getServerMetrics.bind(service));
  apiServer.put(
    `${apiPrefix}/server/access-key-data-limit`,
    service.setDefaultDataLimit.bind(service)
  );
  apiServer.del(
    `${apiPrefix}/server/access-key-data-limit`,
    service.removeDefaultDataLimit.bind(service)
  );
  apiServer.put(
    `${apiPrefix}/server/hostname-for-access-keys`,
    service.setHostnameForAccessKeys.bind(service)
  );
  apiServer.put(
    `${apiPrefix}/server/port-for-new-access-keys`,
    service.setPortForNewAccessKeys.bind(service)
  );
  apiServer.put(`${apiPrefix}/server/listeners`, service.setListeners.bind(service));
  apiServer.put(`${apiPrefix}/server/web-server`, service.configureCaddyWebServer.bind(service));

  apiServer.post(`${apiPrefix}/access-keys`, service.createNewAccessKey.bind(service));
  apiServer.put(`${apiPrefix}/access-keys/:id`, service.createAccessKey.bind(service));
  apiServer.get(`${apiPrefix}/access-keys`, service.listAccessKeys.bind(service));

  apiServer.get(`${apiPrefix}/access-keys/:id`, service.getAccessKey.bind(service));
  apiServer.put(
    `${apiPrefix}/access-keys/:id/listeners`,
    service.setAccessKeyListeners.bind(service)
  );
  apiServer.get(
    `${apiPrefix}/access-keys/:id/dynamic-config`,
    service.getAccessKeyDynamicConfig.bind(service)
  );
  apiServer.del(`${apiPrefix}/access-keys/:id`, service.removeAccessKey.bind(service));
  apiServer.put(`${apiPrefix}/access-keys/:id/name`, service.renameAccessKey.bind(service));
  apiServer.put(
    `${apiPrefix}/access-keys/:id/data-limit`,
    service.setAccessKeyDataLimit.bind(service)
  );
  apiServer.del(
    `${apiPrefix}/access-keys/:id/data-limit`,
    service.removeAccessKeyDataLimit.bind(service)
  );

  apiServer.get(`${apiPrefix}/metrics/transfer`, service.getDataUsage.bind(service));
  apiServer.get(`${apiPrefix}/metrics/enabled`, service.getShareMetrics.bind(service));
  apiServer.put(`${apiPrefix}/metrics/enabled`, service.setShareMetrics.bind(service));

  // Experimental APIs.

  // Redirect former experimental APIs
  apiServer.put(
    `${apiPrefix}/experimental/access-key-data-limit`,
    redirect(`${apiPrefix}/server/access-key-data-limit`)
  );
  apiServer.del(
    `${apiPrefix}/experimental/access-key-data-limit`,
    redirect(`${apiPrefix}/server/access-key-data-limit`)
  );
}

// Returns a request handler that redirects a bound request path to `url` with HTTP status code 308.
function redirect(url: string): restify.RequestHandlerType {
  return (req: restify.Request, res: restify.Response, next: restify.Next) => {
    logging.debug(`Redirecting ${req.url} => ${url}`);
    res.redirect(308, url, next);
  };
}

export function convertTimeRangeToSeconds(timeRange: string): number {
  const TIME_RANGE_UNIT_TO_SECONDS_MULTIPLYER = {
    s: 1,
    h: 60 * 60,
    d: 24 * 60 * 60,
    w: 7 * 24 * 60 * 60,
  };

  const timeRangeValue = Number(timeRange.slice(0, -1));
  const timeRangeUnit = timeRange.slice(-1);

  if (isNaN(timeRangeValue) || !TIME_RANGE_UNIT_TO_SECONDS_MULTIPLYER[timeRangeUnit]) {
    throw new TypeError(`Invalid time range: ${timeRange}`);
  }

  return timeRangeValue * TIME_RANGE_UNIT_TO_SECONDS_MULTIPLYER[timeRangeUnit];
}

function validateAccessKeyId(accessKeyId: unknown): string {
  if (!accessKeyId) {
    throw new restifyErrors.MissingParameterError({statusCode: 400}, 'Parameter `id` is missing');
  } else if (typeof accessKeyId !== 'string') {
    throw new restifyErrors.InvalidArgumentError(
      {statusCode: 400},
      'Parameter `id` must be of type string'
    );
  }
  return accessKeyId;
}

function validateDataLimit(limit: unknown): DataLimit | undefined {
  if (typeof limit === 'undefined') {
    return undefined;
  }

  const bytes = (limit as DataLimit).bytes;
  if (!(Number.isInteger(bytes) && bytes >= 0)) {
    throw new restifyErrors.InvalidArgumentError(
      {statusCode: 400},
      '`limit.bytes` must be an non-negative integer'
    );
  }
  return limit as DataLimit;
}

function validateStringParam(param: unknown, paramName: string): string | undefined {
  if (typeof param === 'undefined') {
    return undefined;
  }

  if (typeof param !== 'string') {
    throw new restifyErrors.InvalidArgumentError(
      {statusCode: 400},
      `Expected a string for ${paramName}, instead got ${param} of type ${typeof param}`
    );
  }
  return param;
}

function validateNumberParam(param: unknown, paramName: string): number | undefined {
  if (typeof param === 'undefined') {
    return undefined;
  }

  if (typeof param !== 'number') {
    throw new restifyErrors.InvalidArgumentError(
      {statusCode: 400},
      `Expected a number for ${paramName}, instead got ${param} of type ${typeof param}`
    );
  }
  return param;
}

// The ShadowsocksManagerService manages the access keys that can use the server
// as a proxy using Shadowsocks. It runs an instance of the Shadowsocks server
// for each existing access key, with the port and password assigned for that access key.
export class ShadowsocksManagerService {
  constructor(
    private defaultServerName: string,
    private serverConfig: JsonConfig<ServerConfigJson>,
    private accessKeys: AccessKeyRepository,
    private shadowsocksServer: ShadowsocksServer,
    private managerMetrics: ManagerMetrics,
    private metricsPublisher: SharedMetricsPublisher,
    private readonly caddyServer?: OutlineCaddyController
  ) {}

  // Creates an AccessKey API response JSON object.
  // For WSS-only keys, omits SS-specific fields (password, port, method, accessUrl)
  // since they're redundant with dynamicConfig and not functional for direct connections.
  private accessKeyToApiJson(accessKey: AccessKey): AccessKeyJson {
    // Determine what types of listeners are enabled
    const hasDirectListeners =
      !accessKey.listeners ||
      accessKey.listeners.includes('tcp') ||
      accessKey.listeners.includes('udp');

    const hasWebSocketListeners =
      accessKey.listeners?.includes('websocket-stream') ||
      accessKey.listeners?.includes('websocket-packet');

    // Start with fields that are always present
    const result: AccessKeyJson = {
      id: accessKey.id,
      name: accessKey.name,
    };

    // Only include SS-specific fields if direct SS connections are supported
    if (hasDirectListeners) {
      result.password = accessKey.proxyParams.password;
      result.port = accessKey.proxyParams.portNumber;
      result.method = accessKey.proxyParams.encryptionMethod;
      result.dataLimit = accessKey.dataLimit;
      result.accessUrl = SIP002_URI.stringify(
        makeConfig({
          host: accessKey.proxyParams.hostname,
          port: accessKey.proxyParams.portNumber,
          method: accessKey.proxyParams.encryptionMethod,
          password: accessKey.proxyParams.password,
          outline: 1,
        })
      );
    } else if (accessKey.dataLimit) {
      // For WSS-only keys, include dataLimit only when set (limits still apply server-side)
      result.dataLimit = accessKey.dataLimit;
    }

    // Include listeners if present
    if (accessKey.listeners) {
      result.listeners = accessKey.listeners;
    }

    // For WebSocket-enabled keys, include the dynamic config as a JSON object
    if (hasWebSocketListeners) {
      const configData = this.serverConfig.data();
      const domain = configData?.caddyWebServer?.domain || configData?.hostname;

      if (domain) {
        const listenersConfig = configData?.listeners;

        // Cast to access generateDynamicAccessKeyConfig method
        const serverWithDynamicConfig = this.shadowsocksServer as ShadowsocksServer & {
          generateDynamicAccessKeyConfig?: (
            proxyParams: {encryptionMethod: string; password: string},
            domain: string,
            tcpPath: string,
            udpPath: string,
            tls: boolean,
            listeners?: ListenerType[]
          ) => Record<string, unknown> | null;
        };

        const dynamicConfig = serverWithDynamicConfig.generateDynamicAccessKeyConfig?.(
          accessKey.proxyParams,
          domain,
          listenersConfig?.websocketStream?.path || '/tcp',
          listenersConfig?.websocketPacket?.path || '/udp',
          configData?.caddyWebServer?.autoHttps !== false,
          accessKey.listeners
        );

        if (dynamicConfig) {
          result.dynamicConfig = dynamicConfig;
        }
      }
    }

    return result;
  }

  renameServer(req: RequestType, res: ResponseType, next: restify.Next): void {
    logging.debug(`renameServer request ${JSON.stringify(req.params)}`);
    const name = req.params.name;
    if (!name) {
      return next(
        new restifyErrors.MissingParameterError({statusCode: 400}, 'Parameter `name` is missing')
      );
    }
    if (typeof name !== 'string' || name.length > 100) {
      next(
        new restifyErrors.InvalidArgumentError(
          `Requested server name should be a string <= 100 characters long.  Got ${name}`
        )
      );
      return;
    }
    const configData = this.serverConfig.data();
    if (configData) {
      configData.name = name;
    }
    this.serverConfig.write();
    res.send(HttpSuccess.NO_CONTENT);
    next();
  }

  getServer(req: RequestType, res: ResponseType, next: restify.Next): void {
    const configData = this.serverConfig.data();
    res.send(HttpSuccess.OK, {
      name: configData?.name || this.defaultServerName,
      serverId: configData?.serverId,
      metricsEnabled: configData?.metricsEnabled || false,
      createdTimestampMs: configData?.createdTimestampMs,
      version: version.getPackageVersion(),
      accessKeyDataLimit: configData?.accessKeyDataLimit,
      portForNewAccessKeys: configData?.portForNewAccessKeys,
      hostnameForAccessKeys: configData?.hostname,
      experimental: configData?.experimental,
    });
    next();
  }

  // Changes the server's hostname.  Hostname must be a valid domain or IP address
  async setHostnameForAccessKeys(
    req: RequestType,
    res: ResponseType,
    next: restify.Next
  ): Promise<void> {
    logging.debug(`changeHostname request: ${JSON.stringify(req.params)}`);

    const hostname = req.params.hostname;
    if (typeof hostname === 'undefined') {
      return next(
        new restifyErrors.MissingParameterError({statusCode: 400}, 'hostname must be provided')
      );
    }
    if (typeof hostname !== 'string') {
      return next(
        new restifyErrors.InvalidArgumentError(
          {statusCode: 400},
          `Expected hostname to be a string, instead got ${hostname} of type ${typeof hostname}`
        )
      );
    }
    // Hostnames can have any number of segments of alphanumeric characters and hyphens, separated
    // by periods. No segment may start or end with a hyphen.
    const hostnameRegex =
      /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;
    if (!hostnameRegex.test(hostname) && !ipRegex({includeBoundaries: true}).test(hostname)) {
      return next(
        new restifyErrors.InvalidArgumentError(
          {statusCode: 400},
          `Hostname ${hostname} isn't a valid hostname or IP address`
        )
      );
    }

    const configData = this.serverConfig.data();
    if (configData) {
      configData.hostname = hostname;
    }
    this.serverConfig.write();
    this.accessKeys.setHostname(hostname);
    try {
      await this.updateCaddyConfig();
    } catch (error) {
      return next(new restifyErrors.InternalServerError(error));
    }
    res.send(HttpSuccess.NO_CONTENT);
    next();
  }

  // Get an access key (always returns JSON)
  getAccessKey(req: RequestType, res: ResponseType, next: restify.Next): void {
    try {
      logging.debug(`getAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const accessKey = this.accessKeys.getAccessKey(accessKeyId);

      // Always return JSON - use /access-keys/{id}/dynamic-config for YAML
      const accessKeyJson = this.accessKeyToApiJson(accessKey);
      logging.debug(`getAccessKey response ${JSON.stringify(accessKeyJson)}`);
      res.send(HttpSuccess.OK, accessKeyJson);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      }
      return next(error);
    }
  }

  // Lists all access keys
  listAccessKeys(req: RequestType, res: ResponseType, next: restify.Next): void {
    logging.debug(`listAccessKeys request ${JSON.stringify(req.params)}`);
    const response = {accessKeys: []};
    for (const accessKey of this.accessKeys.listAccessKeys()) {
      response.accessKeys.push(this.accessKeyToApiJson(accessKey));
    }
    logging.debug(`listAccessKeys response ${JSON.stringify(response)}`);
    res.send(HttpSuccess.OK, response);
    return next();
  }

  private async createAccessKeyFromRequest(req: RequestType, id?: string): Promise<AccessKeyJson> {
    try {
      const encryptionMethod = validateStringParam(req.params.method || '', 'encryptionMethod');
      const name = validateStringParam(req.params.name || '', 'name');
      const dataLimit = validateDataLimit(req.params.limit);
      const password = validateStringParam(req.params.password, 'password');
      const portNumber = validateNumberParam(req.params.port, 'port');

      // Validate listeners if provided
      let listeners = req.params.listeners as string[] | undefined;
      if (listeners) {
        if (!Array.isArray(listeners)) {
          throw new restifyErrors.InvalidArgumentError(
            {statusCode: 400},
            'listeners must be an array'
          );
        }
        const validListeners = ['tcp', 'udp', 'websocket-stream', 'websocket-packet'];
        for (const listener of listeners) {
          if (validListeners.indexOf(listener) === -1) {
            throw new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              `Invalid listener type: ${listener}`
            );
          }
        }
      } else {
        // If no listeners specified, use default listeners based on server config
        const serverListeners = this.serverConfig.data()?.listeners;
        if (serverListeners) {
          listeners = [];
          if (serverListeners.tcp) listeners.push('tcp');
          if (serverListeners.udp) listeners.push('udp');
          if (serverListeners.websocketStream) listeners.push('websocket-stream');
          if (serverListeners.websocketPacket) listeners.push('websocket-packet');
        } else {
          // Default to TCP and UDP if nothing is configured
          listeners = ['tcp', 'udp'];
        }
      }

      const accessKeyJson = this.accessKeyToApiJson(
        await this.accessKeys.createNewAccessKey({
          encryptionMethod,
          id,
          name,
          dataLimit,
          password,
          portNumber,
          listeners: listeners as ListenerType[],
        })
      );
      await this.updateCaddyConfig();
      return accessKeyJson;
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.InvalidCipher || error instanceof errors.InvalidPortNumber) {
        throw new restifyErrors.InvalidArgumentError({statusCode: 400}, error.message);
      } else if (
        error instanceof errors.PortUnavailable ||
        error instanceof errors.PasswordConflict
      ) {
        throw new restifyErrors.ConflictError(error.message);
      }
      throw error;
    }
  }

  // Creates a new access key
  async createNewAccessKey(req: RequestType, res: ResponseType, next: restify.Next): Promise<void> {
    try {
      logging.debug(`createNewAccessKey request ${JSON.stringify(req.params)}`);
      if (req.params.id) {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'Parameter `id` is not allowed')
        );
      }
      const accessKeyJson = await this.createAccessKeyFromRequest(req);
      res.send(201, accessKeyJson);
      logging.debug(`createNewAccessKey response ${JSON.stringify(accessKeyJson)}`);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  // Creates an access key with a specific identifier
  async createAccessKey(req: RequestType, res: ResponseType, next: restify.Next): Promise<void> {
    try {
      logging.debug(`createAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const accessKeyJson = await this.createAccessKeyFromRequest(req, accessKeyId);
      res.send(201, accessKeyJson);
      logging.debug(`createAccessKey response ${JSON.stringify(accessKeyJson)}`);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyConflict) {
        return next(new restifyErrors.ConflictError(error.message));
      }
      if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  // Sets the default ports for new access keys
  async setPortForNewAccessKeys(
    req: RequestType,
    res: ResponseType,
    next: restify.Next
  ): Promise<void> {
    try {
      logging.debug(`setPortForNewAccessKeys request ${JSON.stringify(req.params)}`);
      const port = validateNumberParam(req.params.port, 'port');
      if (port === undefined) {
        return next(
          new restifyErrors.MissingParameterError({statusCode: 400}, 'Parameter `port` is missing')
        );
      }
      await this.accessKeys.setPortForNewAccessKeys(port);
      const configData = this.serverConfig.data();
      if (configData) {
        configData.portForNewAccessKeys = port;
        // Also update listeners config for backward compatibility
        if (!configData.listeners) {
          configData.listeners = {};
        }
        configData.listeners.tcp = {port};
        configData.listeners.udp = {port};
      }
      this.serverConfig.write();
      await this.updateCaddyConfig();
      res.send(HttpSuccess.NO_CONTENT);
      next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.InvalidPortNumber) {
        return next(new restifyErrors.InvalidArgumentError({statusCode: 400}, error.message));
      } else if (error instanceof errors.PortUnavailable) {
        return next(new restifyErrors.ConflictError(error.message));
      } else if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError(error));
    }
  }

  // Sets the listeners configuration (defaults for new keys, optionally updates all keys)
  async setListeners(req: RequestType, res: ResponseType, next: restify.Next): Promise<void> {
    try {
      logging.debug(`setListeners request ${JSON.stringify(req.params)}`);

      const {applyToExisting, ...listeners} = req.params as unknown as ListenersConfig & {
        applyToExisting?: boolean;
      };
      if (!listeners || typeof listeners !== 'object') {
        return next(
          new restifyErrors.InvalidArgumentError(
            {statusCode: 400},
            'Invalid listeners configuration'
          )
        );
      }

      // Validate TCP listener
      if (listeners.tcp) {
        const tcpPort = listeners.tcp.port;
        if (tcpPort !== undefined) {
          if (typeof tcpPort !== 'number' || tcpPort < 1 || tcpPort > 65535) {
            return next(
              new restifyErrors.InvalidArgumentError({statusCode: 400}, 'Invalid TCP port')
            );
          }
        }
      }

      // Validate UDP listener
      if (listeners.udp) {
        const udpPort = listeners.udp.port;
        if (udpPort !== undefined) {
          if (typeof udpPort !== 'number' || udpPort < 1 || udpPort > 65535) {
            return next(
              new restifyErrors.InvalidArgumentError({statusCode: 400}, 'Invalid UDP port')
            );
          }
        }
      }

      // Validate WebSocket listeners
      if (listeners.websocketStream) {
        if (!listeners.websocketStream.path || typeof listeners.websocketStream.path !== 'string') {
          return next(
            new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              'WebSocket stream path is required'
            )
          );
        }
        if (!listeners.websocketStream.path.startsWith('/')) {
          return next(
            new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              'WebSocket stream path must start with /'
            )
          );
        }
        const wsPort = listeners.websocketStream.webServerPort;
        if (wsPort !== undefined) {
          if (typeof wsPort !== 'number' || wsPort < 1 || wsPort > 65535) {
            return next(
              new restifyErrors.InvalidArgumentError(
                {statusCode: 400},
                'Invalid WebSocket server port'
              )
            );
          }
        }
      }

      if (listeners.websocketPacket) {
        if (!listeners.websocketPacket.path || typeof listeners.websocketPacket.path !== 'string') {
          return next(
            new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              'WebSocket packet path is required'
            )
          );
        }
        if (!listeners.websocketPacket.path.startsWith('/')) {
          return next(
            new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              'WebSocket packet path must start with /'
            )
          );
        }
        const wsPacketPort = listeners.websocketPacket.webServerPort;
        if (wsPacketPort !== undefined) {
          if (typeof wsPacketPort !== 'number' || wsPacketPort < 1 || wsPacketPort > 65535) {
            return next(
              new restifyErrors.InvalidArgumentError(
                {statusCode: 400},
                'Invalid WebSocket server port'
              )
            );
          }
        }
      }

      if (
        listeners.websocketStream?.webServerPort !== undefined &&
        listeners.websocketPacket?.webServerPort !== undefined &&
        listeners.websocketStream.webServerPort !== listeners.websocketPacket.webServerPort
      ) {
        return next(
          new restifyErrors.InvalidArgumentError(
            {statusCode: 400},
            'WebSocket stream and packet listeners must share the same web server port'
          )
        );
      }

      // Store the listeners configuration
      const configData = this.serverConfig.data();
      if (configData) {
        configData.listeners = listeners;

        // Update legacy portForNewAccessKeys if TCP port is set
        if (listeners.tcp?.port) {
          configData.portForNewAccessKeys = listeners.tcp.port;
          await this.accessKeys.setPortForNewAccessKeys(listeners.tcp.port);
        }
      }

      // If applyToExisting is true, update all existing keys
      if (applyToExisting) {
        const derivedListeners: ListenerType[] = [];
        if (listeners.tcp) derivedListeners.push('tcp');
        if (listeners.udp) derivedListeners.push('udp');
        if (listeners.websocketStream) derivedListeners.push('websocket-stream');
        if (listeners.websocketPacket) derivedListeners.push('websocket-packet');

        this.accessKeys.setListenersForAllKeys(derivedListeners);
      }

      // Update the underlying Shadowsocks server with the new listener defaults.
      const listenerSettings =
        listeners.websocketStream || listeners.websocketPacket
          ? {
              websocketStream: listeners.websocketStream,
              websocketPacket: listeners.websocketPacket,
            }
          : undefined;
      this.shadowsocksServer.configureListeners?.(listenerSettings);
      this.serverConfig.write();
      await this.updateCaddyConfig();
      res.send(HttpSuccess.NO_CONTENT);
      next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.InvalidPortNumber) {
        return next(new restifyErrors.InvalidArgumentError({statusCode: 400}, error.message));
      } else if (error instanceof errors.PortUnavailable) {
        return next(new restifyErrors.ConflictError(error.message));
      } else if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError(error));
    }
  }

  // Configure Caddy web server for automatic HTTPS
  async configureCaddyWebServer(
    req: RequestType,
    res: ResponseType,
    next: restify.Next
  ): Promise<void> {
    try {
      logging.debug(`configureCaddyWebServer request ${JSON.stringify(req.params)}`);

      const config = req.params as unknown as WebServerConfig;
      if (!config || typeof config !== 'object') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'Invalid Caddy configuration')
        );
      }

      // Validate configuration
      if (config.enabled !== undefined && typeof config.enabled !== 'boolean') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'enabled must be a boolean')
        );
      }

      if (config.autoHttps !== undefined && typeof config.autoHttps !== 'boolean') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'autoHttps must be a boolean')
        );
      }

      if (config.email && typeof config.email !== 'string') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'email must be a string')
        );
      }

      if (config.domain && typeof config.domain !== 'string') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'domain must be a string')
        );
      }

      if (config.apiProxyPath && typeof config.apiProxyPath !== 'string') {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'apiProxyPath must be a string')
        );
      }

      // Store Caddy configuration
      const configData = this.serverConfig.data();
      if (configData) {
        const caddyConfig: WebServerConfig = {
          enabled: config.enabled ?? false,
          autoHttps: config.autoHttps ?? false,
          email: config.email,
          domain: config.domain,
        };
        if (config.apiProxyPath) {
          caddyConfig.apiProxyPath = config.apiProxyPath;
        }
        configData.caddyWebServer = caddyConfig;
      }

      this.serverConfig.write();
      await this.updateCaddyConfig();
      res.send(HttpSuccess.NO_CONTENT);
      next();
    } catch (error) {
      logging.error(error);
      return next(new restifyErrors.InternalServerError(error));
    }
  }

  // Updates listeners for a specific access key
  async setAccessKeyListeners(
    req: RequestType,
    res: ResponseType,
    next: restify.Next
  ): Promise<void> {
    try {
      logging.debug(`setAccessKeyListeners request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);

      const listenersParam = req.params.listeners as string[] | undefined;
      if (!listenersParam || !Array.isArray(listenersParam)) {
        return next(
          new restifyErrors.InvalidArgumentError({statusCode: 400}, 'listeners must be an array')
        );
      }

      const validListeners = ['tcp', 'udp', 'websocket-stream', 'websocket-packet'];
      for (const listener of listenersParam) {
        if (!validListeners.includes(listener)) {
          return next(
            new restifyErrors.InvalidArgumentError(
              {statusCode: 400},
              `Invalid listener type: ${listener}`
            )
          );
        }
      }

      this.accessKeys.setAccessKeyListeners(accessKeyId, listenersParam as ListenerType[]);
      await this.updateCaddyConfig();
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  // Returns dynamic config YAML for WebSocket-enabled keys
  getAccessKeyDynamicConfig(req: RequestType, res: ResponseType, next: restify.Next): void {
    try {
      logging.debug(`getAccessKeyDynamicConfig request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const accessKey = this.accessKeys.getAccessKey(accessKeyId);

      const hasWebSocketListeners =
        accessKey.listeners &&
        (accessKey.listeners.includes('websocket-stream') ||
          accessKey.listeners.includes('websocket-packet'));

      if (!hasWebSocketListeners) {
        return next(
          new restifyErrors.NotFoundError('Access key has no WebSocket listeners configured')
        );
      }

      const configData = this.serverConfig.data();
      const domain = configData?.caddyWebServer?.domain || configData?.hostname;

      if (!domain) {
        return next(
          new restifyErrors.InternalServerError('No domain configured for WebSocket URLs')
        );
      }

      const listenersConfig = configData?.listeners;
      const serverWithWebSocket = this.shadowsocksServer as ShadowsocksServer & {
        generateDynamicAccessKeyYaml?: (
          proxyParams: {encryptionMethod: string; password: string},
          domain: string,
          tcpPath: string,
          udpPath: string,
          tls: boolean,
          listeners?: ListenerType[]
        ) => string | null;
      };

      const yamlConfig = serverWithWebSocket.generateDynamicAccessKeyYaml?.(
        accessKey.proxyParams,
        domain,
        listenersConfig?.websocketStream?.path || '/tcp',
        listenersConfig?.websocketPacket?.path || '/udp',
        configData?.caddyWebServer?.autoHttps !== false,
        accessKey.listeners
      );

      if (!yamlConfig) {
        return next(new restifyErrors.InternalServerError('Failed to generate dynamic config'));
      }

      const nodeResponse = res as unknown as {
        setHeader: (name: string, value: string) => void;
        statusCode: number;
        write: (data: string) => void;
        end: () => void;
      };
      nodeResponse.setHeader('Content-Type', 'text/yaml; charset=utf-8');
      nodeResponse.statusCode = HttpSuccess.OK;
      nodeResponse.write(yamlConfig);
      nodeResponse.end();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      }
      return next(error);
    }
  }

  // Removes an existing access key
  async removeAccessKey(req: RequestType, res: ResponseType, next: restify.Next): Promise<void> {
    try {
      logging.debug(`removeAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      this.accessKeys.removeAccessKey(accessKeyId);
      await this.updateCaddyConfig();
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      } else if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  renameAccessKey(req: RequestType, res: ResponseType, next: restify.Next): void {
    try {
      logging.debug(`renameAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const name = req.params.name;
      if (!name) {
        return next(
          new restifyErrors.MissingParameterError({statusCode: 400}, 'Parameter `name` is missing')
        );
      } else if (typeof name !== 'string') {
        return next(
          new restifyErrors.InvalidArgumentError(
            {statusCode: 400},
            'Parameter `name` must be of type string'
          )
        );
      }
      this.accessKeys.renameAccessKey(accessKeyId, name);
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      } else if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  async setAccessKeyDataLimit(req: RequestType, res: ResponseType, next: restify.Next) {
    try {
      logging.debug(`setAccessKeyDataLimit request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const limit = validateDataLimit(req.params.limit);
      // Enforcement is done asynchronously in the proxy server.  This is transparent to the manager
      // so this doesn't introduce any race conditions between the server and UI.
      this.accessKeys.setAccessKeyDataLimit(accessKeyId, limit);
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      }
      return next(error);
    }
  }

  async removeAccessKeyDataLimit(req: RequestType, res: ResponseType, next: restify.Next) {
    try {
      logging.debug(`removeAccessKeyDataLimit request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      // Enforcement is done asynchronously in the proxy server.  This is transparent to the manager
      // so this doesn't introduce any race conditions between the server and UI.
      this.accessKeys.removeAccessKeyDataLimit(accessKeyId);
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof errors.AccessKeyNotFound) {
        return next(new restifyErrors.NotFoundError(error.message));
      }
      return next(error);
    }
  }

  async setDefaultDataLimit(req: RequestType, res: ResponseType, next: restify.Next) {
    try {
      logging.debug(`setDefaultDataLimit request ${JSON.stringify(req.params)}`);
      const limit = validateDataLimit(req.params.limit);
      // Enforcement is done asynchronously in the proxy server.  This is transparent to the manager
      // so this doesn't introduce any race conditions between the server and UI.
      this.accessKeys.setDefaultDataLimit(limit);
      const configData = this.serverConfig.data();
      if (configData) {
        configData.accessKeyDataLimit = limit;
      }
      this.serverConfig.write();
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      if (error instanceof restifyErrors.HttpError) {
        return next(error);
      }
      return next(new restifyErrors.InternalServerError());
    }
  }

  async removeDefaultDataLimit(req: RequestType, res: ResponseType, next: restify.Next) {
    try {
      logging.debug(`removeDefaultDataLimit request ${JSON.stringify(req.params)}`);
      // Enforcement is done asynchronously in the proxy server.  This is transparent to the manager
      // so this doesn't introduce any race conditions between the server and UI.
      this.accessKeys.removeDefaultDataLimit();
      const configData = this.serverConfig.data();
      if (configData) {
        delete configData.accessKeyDataLimit;
      }
      this.serverConfig.write();
      res.send(HttpSuccess.NO_CONTENT);
      return next();
    } catch (error) {
      logging.error(error);
      return next(new restifyErrors.InternalServerError());
    }
  }

  async getDataUsage(req: RequestType, res: ResponseType, next: restify.Next) {
    try {
      logging.debug(`getDataUsage request ${JSON.stringify(req.params)}`);
      const response = await this.managerMetrics.getOutboundByteTransfer({hours: 30 * 24});
      res.send(HttpSuccess.OK, response);
      logging.debug(`getDataUsage response ${JSON.stringify(response)}`);
      return next();
    } catch (error) {
      logging.error(error);
      return next(new restifyErrors.InternalServerError());
    }
  }

  async getServerMetrics(req: RequestType, res: ResponseType, next: restify.Next) {
    logging.debug(`getServerMetrics request ${JSON.stringify(req.params)}`);

    let seconds;
    try {
      if (!req.query?.since) {
        return next(
          new restifyErrors.MissingParameterError({statusCode: 400}, 'Parameter `since` is missing')
        );
      }

      seconds = convertTimeRangeToSeconds(req.query.since as string);
    } catch (error) {
      logging.error(error);
      return next(new restifyErrors.InvalidArgumentError({statusCode: 400}, error.message));
    }

    try {
      const response = await this.managerMetrics.getServerMetrics({seconds});
      res.send(HttpSuccess.OK, response);
      logging.debug(`getServerMetrics response ${JSON.stringify(response)}`);
      return next();
    } catch (error) {
      logging.error(error);
      return next(new restifyErrors.InternalServerError());
    }
  }

  getShareMetrics(req: RequestType, res: ResponseType, next: restify.Next): void {
    logging.debug(`getShareMetrics request ${JSON.stringify(req.params)}`);
    const response = {metricsEnabled: this.metricsPublisher.isSharingEnabled()};
    res.send(HttpSuccess.OK, response);
    logging.debug(`getShareMetrics response: ${JSON.stringify(response)}`);
    next();
  }

  setShareMetrics(req: RequestType, res: ResponseType, next: restify.Next): void {
    logging.debug(`setShareMetrics request ${JSON.stringify(req.params)}`);
    const metricsEnabled = req.params.metricsEnabled;
    if (metricsEnabled === undefined || metricsEnabled === null) {
      return next(
        new restifyErrors.MissingParameterError(
          {statusCode: 400},
          'Parameter `metricsEnabled` is missing'
        )
      );
    } else if (typeof metricsEnabled !== 'boolean') {
      return next(
        new restifyErrors.InvalidArgumentError(
          {statusCode: 400},
          'Parameter `metricsEnabled` must be a boolean'
        )
      );
    }
    if (metricsEnabled) {
      this.metricsPublisher.startSharing();
    } else {
      this.metricsPublisher.stopSharing();
    }
    res.send(HttpSuccess.NO_CONTENT);
    next();
  }

  private async updateCaddyConfig(): Promise<void> {
    if (!this.caddyServer) {
      return;
    }
    const configData = this.serverConfig.data();
    if (!configData) {
      return;
    }
    try {
      // Pass API port when apiProxyPath is configured
      const apiPortNumber = Number(process.env.SB_API_PORT) || 8443;
      const apiPort = configData.caddyWebServer?.apiProxyPath ? apiPortNumber : undefined;
      await this.caddyServer.applyConfig({
        accessKeys: this.accessKeys.listAccessKeys(),
        listeners: configData.listeners,
        caddyConfig: configData.caddyWebServer,
        hostname: configData.hostname,
        apiPort,
      });
    } catch (error) {
      logging.error(`Failed to apply Caddy configuration: ${error}`);
      throw error;
    }
  }
}
