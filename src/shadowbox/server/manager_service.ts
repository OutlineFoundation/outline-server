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
import {AccessKey, AccessKeyRepository, DataLimit} from '../model/access_key';
import * as errors from '../model/errors';
import * as version from './version';

import {ManagerMetrics} from './manager_metrics';
import {ServerConfigJson} from './server_config';
import {SharedMetricsPublisher} from './shared_metrics';
import {ShadowsocksServer} from '../model/shadowsocks_server';

interface AccessKeyJson {
  // The unique identifier of this access key.
  id: string;
  // Admin-controlled, editable name for this access key.
  name: string;
  // Shadowsocks-specific details and credentials.
  password: string;
  port: number;
  method: string;
  dataLimit: DataLimit;
  accessUrl: string;
}

// Creates a AccessKey response.
function accessKeyToApiJson(accessKey: AccessKey): AccessKeyJson {
  return {
    id: accessKey.id,
    name: accessKey.name,
    password: accessKey.proxyParams.password,
    port: accessKey.proxyParams.portNumber,
    method: accessKey.proxyParams.encryptionMethod,
    dataLimit: accessKey.dataLimit,
    accessUrl: SIP002_URI.stringify(
      makeConfig({
        host: accessKey.proxyParams.hostname,
        port: accessKey.proxyParams.portNumber,
        method: accessKey.proxyParams.encryptionMethod,
        password: accessKey.proxyParams.password,
        outline: 1,
      })
    ),
  };
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

  apiServer.post(`${apiPrefix}/access-keys`, service.createNewAccessKey.bind(service));
  apiServer.put(`${apiPrefix}/access-keys/:id`, service.createAccessKey.bind(service));
  apiServer.get(`${apiPrefix}/access-keys`, service.listAccessKeys.bind(service));

  apiServer.get(`${apiPrefix}/access-keys/:id`, service.getAccessKey.bind(service));
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
    private metricsPublisher: SharedMetricsPublisher
  ) {}

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
    this.serverConfig.data().name = name;
    this.serverConfig.write();
    res.send(HttpSuccess.NO_CONTENT);
    next();
  }

  getServer(req: RequestType, res: ResponseType, next: restify.Next): void {
    res.send(HttpSuccess.OK, {
      name: this.serverConfig.data().name || this.defaultServerName,
      serverId: this.serverConfig.data().serverId,
      metricsEnabled: this.serverConfig.data().metricsEnabled || false,
      createdTimestampMs: this.serverConfig.data().createdTimestampMs,
      version: version.getPackageVersion(),
      accessKeyDataLimit: this.serverConfig.data().accessKeyDataLimit,
      portForNewAccessKeys: this.serverConfig.data().portForNewAccessKeys,
      hostnameForAccessKeys: this.serverConfig.data().hostname,
      experimental: this.serverConfig.data().experimental,
    });
    next();
  }

  // Changes the server's hostname.  Hostname must be a valid domain or IP address
  setHostnameForAccessKeys(req: RequestType, res: ResponseType, next: restify.Next): void {
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

    this.serverConfig.data().hostname = hostname;
    this.serverConfig.write();
    this.accessKeys.setHostname(hostname);
    res.send(HttpSuccess.NO_CONTENT);
    next();
  }

  // Get a access key
  getAccessKey(req: RequestType, res: ResponseType, next: restify.Next): void {
    try {
      logging.debug(`getAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      const accessKey = this.accessKeys.getAccessKey(accessKeyId);
      const accessKeyJson = accessKeyToApiJson(accessKey);

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
      response.accessKeys.push(accessKeyToApiJson(accessKey));
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

      const accessKeyJson = accessKeyToApiJson(
        await this.accessKeys.createNewAccessKey({
          encryptionMethod,
          id,
          name,
          dataLimit,
          password,
          portNumber,
        })
      );
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
      this.serverConfig.data().portForNewAccessKeys = port;
      this.serverConfig.write();
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

  // Removes an existing access key
  removeAccessKey(req: RequestType, res: ResponseType, next: restify.Next): void {
    try {
      logging.debug(`removeAccessKey request ${JSON.stringify(req.params)}`);
      const accessKeyId = validateAccessKeyId(req.params.id);
      this.accessKeys.removeAccessKey(accessKeyId);
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
      this.serverConfig.data().accessKeyDataLimit = limit;
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
      delete this.serverConfig.data().accessKeyDataLimit;
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
    logging.debug(`getServerMetrics request ${JSON.stringify(req.query)}`);

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
}
