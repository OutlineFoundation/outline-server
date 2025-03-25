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

import {
  PrometheusClient,
  PrometheusMetric,
  PrometheusValue,
  QueryResultData,
} from '../infrastructure/prometheus_scraper';
import {DataUsageByUser, DataUsageTimeframe} from '../model/metrics';

const PROMETHEUS_RANGE_QUERY_STEP_SECONDS = 5 * 60;

interface Duration {
  seconds: number;
}

interface Data {
  bytes: number;
}

interface TimedData<T> {
  data: T;
  timestamp: number | null;
}

interface ConnectionStats {
  lastTrafficSeen: number | null;
  peakDeviceCount: TimedData<number>;
}

interface BandwidthStats {
  current: TimedData<Data>;
  peak: TimedData<Data>;
}

interface ServerMetricsServerEntry {
  tunnelTime: Duration;
  dataTransferred: Data;
  bandwidth: BandwidthStats;
  locations: ServerMetricsLocationEntry[];
}

interface ServerMetricsLocationEntry {
  location: string;
  asn: number | null;
  asOrg: string | null;
  tunnelTime: Duration;
  dataTransferred: Data;
}

interface ServerMetricsAccessKeyEntry {
  accessKeyId: number;
  tunnelTime: Duration;
  dataTransferred: Data;
  connection: ConnectionStats;
}

interface ServerMetrics {
  server: ServerMetricsServerEntry;
  accessKeys: ServerMetricsAccessKeyEntry[];
}

export interface ManagerMetrics {
  getOutboundByteTransfer(timeframe: DataUsageTimeframe): Promise<DataUsageByUser>;
  getServerMetrics(timeframe: Duration): Promise<ServerMetrics>;
}

// Reads manager metrics from a Prometheus instance.
export class PrometheusManagerMetrics implements ManagerMetrics {
  constructor(private prometheusClient: PrometheusClient) {}

  async getOutboundByteTransfer(timeframe: DataUsageTimeframe): Promise<DataUsageByUser> {
    // TODO(fortuna): Consider pre-computing this to save server's CPU.
    // We measure only traffic leaving the server, since that's what DigitalOcean charges.
    // TODO: Display all directions to admin
    const result = await this.prometheusClient.query(
      `sum(increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[${timeframe.hours}h])) by (access_key)`
    );
    const usage = {} as {[userId: string]: number};
    for (const entry of result.result) {
      const bytes = Math.round(parseFloat(entry.value[1]));
      if (bytes === 0) {
        continue;
      }
      usage[entry.metric['access_key'] || ''] = bytes;
    }
    return {bytesTransferredByUserId: usage};
  }

  async getServerMetrics(timeframe: Duration): Promise<ServerMetrics> {
    const now = new Date().getTime() / 1000;
    // We need to calculate consistent start and end times for Prometheus range
    // queries. Rounding the end time *up* to the nearest multiple of the step
    // prevents time "drift" between queries, which is crucial for reliable step
    // alignment and consistent data retrieval, especially when using
    // aggregations like increase() or rate(). This ensures that the same time
    // windows are queried each time, leading to more stable and predictable
    // results.
    const end =
      Math.ceil(now / PROMETHEUS_RANGE_QUERY_STEP_SECONDS) * PROMETHEUS_RANGE_QUERY_STEP_SECONDS;
    const start = end - timeframe.seconds;

    this.prunePrometheusCache();

    const [
      dataTransferredByAccessKeyRange,
      dataTransferredByLocationRange,
      tunnelTimeByAccessKeyRange,
      tunnelTimeByLocation,
    ] = await Promise.all([
      this.cachedPrometheusClient.queryRange(
        `sum(increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s])) by (access_key)`,
        start,
        end,
        `${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s`
      ),
      this.cachedPrometheusClient.queryRange(
        `sum(increase(shadowsocks_data_bytes_per_location{dir=~"c<p|p>t"}[${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s])) by (location, asn, asorg)`,
        start,
        end,
        `${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s`
      ),
      this.cachedPrometheusClient.queryRange(
        `sum(increase(shadowsocks_tunnel_time_seconds[${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s])) by (access_key)`,
        start,
        end,
        `${PROMETHEUS_RANGE_QUERY_STEP_SECONDS}s`
      ),
      this.cachedPrometheusClient.query(
        `sum(increase(shadowsocks_tunnel_time_seconds_per_location[${timeframe.seconds}s])) by (location, asn, asorg)`
      ),
    ]);

    const serverMetrics: ServerMetricsServerEntry = {
      tunnelTime: {seconds: 0},
      dataTransferred: {bytes: 0},
      bandwidth: {
        current: {data: {bytes: 0}, timestamp: null},
        peak: {data: {bytes: 0}, timestamp: null},
      },
      locations: [],
    };

    const bandwidthTimeseriesIndex = new Map<number, string>();

    const accessKeyMap = new Map<string, ServerMetricsAccessKeyEntry>();
    for (const result of dataTransferredByAccessKeyRange.result) {
      const entry = getServerMetricsAccessKeyEntry(accessKeyMap, result.metric);
      const lastTrafficSeen = findLastNonZero(result.values ?? []);

      entry.connection.lastTrafficSeen = lastTrafficSeen ? Math.min(now, lastTrafficSeen[0]) : null;
      entry.dataTransferred.bytes = findSum(result.values ?? []);

      for (const entryIndex in result.values) {
        const [timestamp, value] = result.values[entryIndex];

        bandwidthTimeseriesIndex.set(
          timestamp,
          bandwidthTimeseriesIndex.has(timestamp)
            ? String(
                parseFloat(bandwidthTimeseriesIndex.get(timestamp) as string) + parseFloat(value)
              )
            : value
        );
      }
    }

    const bandwidthRangeValues = [...bandwidthTimeseriesIndex.entries()].sort(
      (a, b) => a[0] - b[0]
    );

    const currentBandwidth = bandwidthRangeValues[bandwidthRangeValues.length - 1] ?? [0, '0'];

    // convert increase() into rate()
    serverMetrics.bandwidth.current.data.bytes =
      parseFloat(currentBandwidth[1]) / PROMETHEUS_RANGE_QUERY_STEP_SECONDS;
    serverMetrics.bandwidth.current.timestamp = currentBandwidth[0];

    const peakDataTransferred = findPeak(bandwidthRangeValues);
    if (peakDataTransferred !== null) {
      const peakValue = parseFloat(peakDataTransferred[1]);

      if (peakValue > 0) {
        // convert increase() into rate()
        serverMetrics.bandwidth.peak.data.bytes = peakValue / PROMETHEUS_RANGE_QUERY_STEP_SECONDS;
        serverMetrics.bandwidth.peak.timestamp = Math.min(now, peakDataTransferred[0]);
      }
    }

    for (const result of tunnelTimeByAccessKeyRange.result) {
      const entry = getServerMetricsAccessKeyEntry(accessKeyMap, result.metric);

      const peakTunnelTimeSec = findPeak(result.values ?? []);
      if (peakTunnelTimeSec !== null) {
        const peakValue = parseFloat(peakTunnelTimeSec[1]);
        if (peakValue > 0) {
          const peakTunnelTimeOverTime = peakValue / PROMETHEUS_RANGE_QUERY_STEP_SECONDS;
          entry.connection.peakDeviceCount.data = Math.ceil(peakTunnelTimeOverTime);
          entry.connection.peakDeviceCount.timestamp = Math.min(now, peakTunnelTimeSec[0]);
        }
      }

      entry.tunnelTime.seconds = findSum(result.values ?? []);
    }

    const locationMap = new Map<string, ServerMetricsLocationEntry>();
    for (const result of dataTransferredByLocationRange.result) {
      const entry = getServerMetricsLocationEntry(locationMap, result.metric);
      const bytes = findSum(result.values ?? []);

      entry.dataTransferred.bytes += bytes;
      serverMetrics.dataTransferred.bytes += bytes;
    }

    for (const result of tunnelTimeByLocation.result) {
      const entry = getServerMetricsLocationEntry(locationMap, result.metric);
      const tunnelTime = result.value ? parseFloat(result.value[1]) : 0;

      entry.tunnelTime.seconds = tunnelTime;
      serverMetrics.tunnelTime.seconds += tunnelTime;
    }

    serverMetrics.locations = Array.from(locationMap.values());

    return {
      server: serverMetrics,
      accessKeys: Array.from(accessKeyMap.values()),
    };
  }

  private prometheusCache = new Map<string, {timestamp: number; result: QueryResultData}>();

  private get cachedPrometheusClient() {
    return new Proxy(this.prometheusClient, {
      get: (target, prop) => {
        if (typeof target[prop] !== 'function') {
          return target[prop];
        }

        return async (query, ...args) => {
          const cacheId = `${String(prop)}: ${query} (args: ${args.join(', ')}))`;

          if (this.prometheusCache.has(cacheId)) {
            return this.prometheusCache.get(cacheId).result;
          }

          const result = await (target[prop] as Function)(query, ...args);

          this.prometheusCache.set(cacheId, {timestamp: Date.now(), result});

          return result;
        };
      },
    });
  }

  private prunePrometheusCache() {
    const now = Date.now();
    for (const [key, value] of this.prometheusCache) {
      if (now - value.timestamp > PROMETHEUS_RANGE_QUERY_STEP_SECONDS * 1000) {
        this.prometheusCache.delete(key);
      }
    }
  }
}

function getServerMetricsLocationEntry(
  map: Map<string, ServerMetricsLocationEntry>,
  metric: PrometheusMetric
): ServerMetricsLocationEntry {
  const {location, asn, asorg} = metric;
  const key = `${location},${asn},${asorg}`;
  let entry = map.get(key);
  if (entry === undefined) {
    entry = {
      location: location,
      asn: asn ? parseInt(asn) : null,
      asOrg: asorg ?? null,
      dataTransferred: {bytes: 0},
      tunnelTime: {seconds: 0},
    };
    map.set(key, entry);
  }
  return entry;
}

function getServerMetricsAccessKeyEntry(
  map: Map<string, ServerMetricsAccessKeyEntry>,
  metric: PrometheusMetric
): ServerMetricsAccessKeyEntry {
  const accessKey = metric['access_key'];
  let entry = map.get(accessKey);
  if (entry === undefined) {
    entry = {
      accessKeyId: parseInt(accessKey),
      dataTransferred: {bytes: 0},
      tunnelTime: {seconds: 0},
      connection: {
        lastTrafficSeen: null,
        peakDeviceCount: {
          data: 0,
          timestamp: null,
        },
      },
    };
    map.set(accessKey, entry);
  }
  return entry;
}

/**
 * Finds the peak PrometheusValue in an array of PrometheusValues.
 *
 * The peak is determined by the highest value. If values are equal, the
 * PrometheusValue with the latest timestamp is considered the peak.
 */
function findPeak(values: PrometheusValue[]): PrometheusValue | null {
  let peak: PrometheusValue | null = null;
  let maxValue = -Infinity;

  for (const value of values) {
    const currentValue = parseFloat(value[1]);
    if (currentValue > maxValue) {
      maxValue = currentValue;
      peak = value;
    } else if (currentValue === maxValue && value[0] > peak[0]) {
      peak = value;
    }
  }

  return peak;
}

/**
 * Finds the last PrometheusValue in an array that has a value greater than zero.
 */
function findLastNonZero(values: PrometheusValue[]): PrometheusValue | null {
  for (let i = values.length - 1; i >= 0; i--) {
    const value = values[i];
    if (parseFloat(value[1]) > 0) {
      return value;
    }
  }
  return null;
}

/**
 * Finds the sum of the values in an array of PrometheusValues.
 */
function findSum(values: PrometheusValue[]): number {
  let sum = 0;
  for (const value of values) {
    sum += parseFloat(value[1]);
  }
  return sum;
}
