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

import * as child_process from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as jsyaml from 'js-yaml';
import fetch from 'node-fetch';
import * as path from 'path';

import * as logging from '../infrastructure/logging';

/**
 * Represents a Unix timestamp in seconds.
 * @typedef {number} Timestamp
 */
type Timestamp = number;

/**
 * Represents a Prometheus metric's labels.
 * Each key in the object is a label name, and the corresponding value is the label's value.
 *
 * @typedef {Object<string, string>} PrometheusMetric
 */
export type PrometheusMetric = {[labelValue: string]: string};

/**
 * Represents a Prometheus value, which is a tuple of a timestamp and a string value.
 * @typedef {[Timestamp, string]} PrometheusValue
 */
export type PrometheusValue = [Timestamp, string];

/**
 * Represents a Prometheus result, which can be a time series (values) or a single value.
 * @typedef {Object} PrometheusResult
 * @property {Object.<string, string>} metric - Labels associated with the metric.
 * @property {Array<PrometheusValue>} [values] - Time series data (for range queries).
 * @property {PrometheusValue} [value] - Single value (for instant queries).
 */
export type PrometheusResult = {
  metric: PrometheusMetric;
  values?: PrometheusValue[];
  value?: PrometheusValue;
};

/**
 * Represents the data part of a Prometheus query result.
 * @interface QueryResultData
 */
export interface QueryResultData {
  resultType: 'matrix' | 'vector' | 'scalar' | 'string';
  result: PrometheusResult[];
}

/**
 * Represents the full JSON response from a Prometheus query.  This interface
 * is based on the Prometheus API documentation:
 * https://prometheus.io/docs/prometheus/latest/querying/api/
 * @interface QueryResult
 */
interface QueryResult {
  status: 'success' | 'error';
  data: QueryResultData;
  errorType: string;
  error: string;
}

/**
 * Interface for a Prometheus client.
 * @interface PrometheusClient
 */
export interface PrometheusClient {
  /**
   * Performs an instant query against the Prometheus API.
   * @function query
   * @param {string} query - The PromQL query string.
   * @returns {Promise<QueryResultData>} A Promise that resolves to the query result data.
   */
  query(query: string): Promise<QueryResultData>;

  /**
   * Performs a range query against the Prometheus API.
   * @function queryRange
   * @param {string} query - The PromQL query string.
   * @param {number} start - The start time for the query range.
   * @param {number} end - The end time for the query range.
   * @param {string} step - The step size for the query range (e.g., "1m", "5m").  This controls the resolution of the returned data.
   * @returns {Promise<QueryResultData>} A Promise that resolves to the query result data.
   */
  queryRange(query: string, start: number, end: number, step: string): Promise<QueryResultData>;
}

export class ApiPrometheusClient implements PrometheusClient {
  private readonly agent: http.Agent;

  constructor(private address: string) {
    this.agent = new http.Agent({keepAlive: true});
  }

  private async request(url: string): Promise<QueryResultData> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(url, {
        agent: this.agent,
        signal: controller.signal,
        redirect: 'error',
      });
      if (!response.ok) {
        throw new Error(`Got error ${response.status}`);
      }
      // Parsing and body-stream errors must reject, not escape an HTTP callback.
      const result = (await response.json()) as QueryResult;
      if (result.status !== 'success') {
        throw new Error(`Error ${result.errorType}: ${result.error}`);
      }
      return result.data;
    } finally {
      clearTimeout(timeout);
      // Also release the connection when status checks or body parsing fail.
      controller.abort();
    }
  }

  query(query: string): Promise<QueryResultData> {
    const url = `${this.address}/api/v1/query?query=${encodeURIComponent(query)}`;
    return this.request(url);
  }

  queryRange(query: string, start: number, end: number, step: string): Promise<QueryResultData> {
    const url = `${this.address}/api/v1/query_range?query=${encodeURIComponent(
      query
    )}&start=${start}&end=${end}&step=${step}`;
    return this.request(url);
  }
}

export async function startPrometheus(
  binaryFilename: string,
  configFilename: string,
  configJson: {},
  processArgs: string[],
  endpoint: string
) {
  await writePrometheusConfigToDisk(configFilename, configJson);
  await spawnPrometheusSubprocess(binaryFilename, processArgs, endpoint);
}

async function writePrometheusConfigToDisk(configFilename: string, configJson: {}) {
  await fs.promises.mkdir(path.dirname(configFilename), {recursive: true});
  const ymlTxt = jsyaml.safeDump(configJson, {sortKeys: true});
  // Write the file asynchronously to prevent blocking the node thread.
  await fs.promises.writeFile(configFilename, ymlTxt, 'utf-8');
}

async function spawnPrometheusSubprocess(
  binaryFilename: string,
  processArgs: string[],
  prometheusEndpoint: string
): Promise<child_process.ChildProcess> {
  let runProcess: child_process.ChildProcess;
  let restartDelayMs = 1000;
  const start = () => {
    logging.info('======== Starting Prometheus ========');
    logging.info(`${binaryFilename} ${processArgs.map((a) => `"${a}"`).join(' ')}`);
    const startedAt = Date.now();
    runProcess = child_process.spawn(binaryFilename, processArgs);
    runProcess.on('error', (error) => {
      logging.error(`Error spawning Prometheus: ${error}`);
    });
    runProcess.once('close', (code, signal) => {
      if (Date.now() - startedAt >= 60000) {
        restartDelayMs = 1000;
      }
      logging.error(
        `Prometheus exited. Code: ${code}, Signal: ${signal}; restarting in ${restartDelayMs}ms`
      );
      setTimeout(start, restartDelayMs);
      restartDelayMs = Math.min(restartDelayMs * 2, 30000);
    });
    runProcess.stdout.pipe(process.stdout);
    runProcess.stderr.pipe(process.stderr);
  };
  start();
  // Use one readiness loop across retries, rather than creating another loop
  // (and an abandoned promise) every time an unready child exits.
  await waitForPrometheusReady(`${prometheusEndpoint}/api/v1/status/flags`);
  logging.info('Prometheus is ready!');
  return runProcess;
}

async function waitForPrometheusReady(prometheusEndpoint: string) {
  while (!(await isHttpEndpointHealthy(prometheusEndpoint))) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

function isHttpEndpointHealthy(endpoint: string): Promise<boolean> {
  return new Promise((resolve, _) => {
    const request = http
      .get(endpoint, (response) => {
        response.resume();
        resolve(response.statusCode >= 200 && response.statusCode < 300);
      })
      .on('error', () => {
        // Prometheus is not ready yet.
        resolve(false);
      });
    // An inactivity timeout can be kept alive by a trickling response. Bound
    // the entire probe instead, including connecting and draining its body.
    const timeout = setTimeout(() => {
      request.destroy();
      resolve(false);
    }, 1000);
    request.once('close', () => clearTimeout(timeout));
  });
}
