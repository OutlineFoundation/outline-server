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

import {Clock} from '../infrastructure/clock';
import * as follow_redirects from '../infrastructure/follow_redirects';
import {JsonConfig} from '../infrastructure/json_config';
import * as logging from '../infrastructure/logging';
import {PrometheusClient, QueryResultData} from '../infrastructure/prometheus_scraper';
import * as version from './version';
import {AccessKeyConfigJson} from './server_access_key';

import {ServerConfigJson} from './server_config';

const MS_PER_HOUR = 60 * 60 * 1000;
const MS_PER_DAY = 24 * MS_PER_HOUR;

export interface ReportedUsage {
  country: string;
  asn?: number;
  inboundBytes: number;
  tunnelTimeSec: number;
}

// JSON format for the published report.
// Field renames will break backwards-compatibility.
export interface HourlyServerMetricsReportJson {
  serverId: string;
  startUtcMs: number;
  endUtcMs: number;
  userReports: HourlyUserMetricsReportJson[];
}

// JSON format for the published report.
// Field renames will break backwards-compatibility.
export interface HourlyUserMetricsReportJson {
  countries: string[];
  asn?: number;
  bytesTransferred: number;
  tunnelTimeSec: number;
}

// JSON format for the feature metrics report.
// Field renames will break backwards-compatibility.
export interface DailyFeatureMetricsReportJson {
  serverId: string;
  serverVersion: string;
  timestampUtcMs: number;
  dataLimit: DailyDataLimitMetricsReportJson;
}

// JSON format for the data limit feature metrics report.
// Field renames will break backwards-compatibility.
export interface DailyDataLimitMetricsReportJson {
  enabled: boolean;
  perKeyLimitCount?: number;
}

export interface SharedMetricsPublisher {
  startSharing();
  stopSharing();
  isSharingEnabled();
}

export interface UsageMetrics {
  getReportedUsage(endTimeMs?: number): Promise<ReportedUsage[]>;
  reset(endTimeMs?: number);
}

// Reads data usage metrics from Prometheus.
export class PrometheusUsageMetrics implements UsageMetrics {
  private resetTimeMs: number = Date.now();

  constructor(private prometheusClient: PrometheusClient) {}

  async getReportedUsage(endTimeMs = Date.now()): Promise<ReportedUsage[]> {
    const timeDeltaMs = Math.max(1, endTimeMs - this.resetTimeMs);
    const selectorTime = `[${timeDeltaMs}ms] @ ${endTimeMs / 1000}`;

    const usage = new Map<string, ReportedUsage>();
    const processResults = (
      data: QueryResultData,
      setValue: (entry: ReportedUsage, value: string) => void
    ) => {
      for (const result of data.result) {
        const country = result.metric['location'] || '';
        const asn = result.metric['asn'] ? Number(result.metric['asn']) : undefined;
        const key = `${country}-${asn}`;
        const entry = usage.get(key) || {
          country,
          asn,
          inboundBytes: 0,
          tunnelTimeSec: 0,
        };
        setValue(entry, result.value[1]);
        if (!usage.has(key)) {
          usage.set(key, entry);
        }
      }
    };

    // Both independent queries use the same snapshot boundary. Traffic during
    // collection/upload belongs to the next report, not to a discarded gap.
    const [dataBytesQueryResponse, tunnelTimeQueryResponse] = await Promise.all([
      this.prometheusClient.query(
        `sum(increase(shadowsocks_data_bytes_per_location{dir=~"p>t|p<t"}${selectorTime})) by (location, asn)`
      ),
      this.prometheusClient.query(
        `sum(increase(shadowsocks_tunnel_time_seconds_per_location${selectorTime})) by (location, asn)`
      ),
    ]);
    processResults(dataBytesQueryResponse, (entry, value) => {
      entry.inboundBytes = Math.round(parseFloat(value));
    });

    processResults(tunnelTimeQueryResponse, (entry, value) => {
      entry.tunnelTimeSec = Math.round(parseFloat(value));
    });

    return Array.from(usage.values());
  }

  reset(endTimeMs = Date.now()) {
    this.resetTimeMs = endTimeMs;
  }
}

export interface MetricsCollectorClient {
  collectServerUsageMetrics(reportJson: HourlyServerMetricsReportJson): Promise<void>;
  collectFeatureMetrics(reportJson: DailyFeatureMetricsReportJson): Promise<void>;
}

export class RestMetricsCollectorClient implements MetricsCollectorClient {
  constructor(private serviceUrl: string) {}

  collectServerUsageMetrics(reportJson: HourlyServerMetricsReportJson): Promise<void> {
    return this.postMetrics('/connections', JSON.stringify(reportJson));
  }

  collectFeatureMetrics(reportJson: DailyFeatureMetricsReportJson): Promise<void> {
    return this.postMetrics('/features', JSON.stringify(reportJson));
  }

  private async postMetrics(urlPath: string, reportJson: string): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    const options = {
      headers: {'Content-Type': 'application/json'},
      method: 'POST',
      body: reportJson,
      signal: controller.signal,
    };
    const url = `${this.serviceUrl}${urlPath}`;
    logging.debug(`Posting metrics to ${url} with options ${JSON.stringify(options)}`);
    try {
      const response = await follow_redirects.requestFollowRedirectsWithSameMethodAndBody(
        url,
        options
      );
      if (!response.ok) {
        throw new Error(`Got status ${response.status}`);
      }
    } catch (e) {
      throw new Error(`Failed to post to metrics server: ${e}`);
    } finally {
      clearTimeout(timeout);
      // Only the status is used. Abort the HTTP request itself, not just its
      // proxy response stream, even when the collector never finishes its body.
      controller.abort();
    }
  }
}

// Keeps track of the connection metrics per user, since the startDatetime.
// This is reported to the Outline team if the admin opts-in.
export class OutlineSharedMetricsPublisher implements SharedMetricsPublisher {
  // Time at which we started recording connection metrics.
  private reportStartTimestampMs: number;
  private reportingUsage = false;
  private reportingFeatures = false;

  // serverConfig: where the enabled/disable setting is persisted
  // keyConfig: where access keys are persisted
  // usageMetrics: where we get the metrics from
  // metricsUrl: where to post the metrics
  constructor(
    private clock: Clock,
    private serverConfig: JsonConfig<ServerConfigJson>,
    private keyConfig: JsonConfig<AccessKeyConfigJson>,
    usageMetrics: UsageMetrics,
    private metricsCollector: MetricsCollectorClient
  ) {
    // Start timer
    this.reportStartTimestampMs = this.clock.now();

    this.clock.setInterval(async () => {
      if (!this.isSharingEnabled() || this.reportingUsage) {
        return;
      }
      this.reportingUsage = true;
      try {
        const reportEndTimestampMs = this.clock.now();
        await this.reportServerUsageMetrics(
          await usageMetrics.getReportedUsage(reportEndTimestampMs),
          reportEndTimestampMs
        );
        usageMetrics.reset(reportEndTimestampMs);
      } catch (err) {
        logging.error(`Failed to report server usage metrics: ${err}`);
      } finally {
        this.reportingUsage = false;
      }
    }, MS_PER_HOUR);
    // TODO(fortuna): also trigger report on shutdown, so data loss is minimized.

    this.clock.setInterval(async () => {
      if (!this.isSharingEnabled() || this.reportingFeatures) {
        return;
      }
      this.reportingFeatures = true;
      try {
        await this.reportFeatureMetrics();
      } catch (err) {
        logging.error(`Failed to report feature metrics: ${err}`);
      } finally {
        this.reportingFeatures = false;
      }
    }, MS_PER_DAY);
  }

  startSharing() {
    this.serverConfig.data().metricsEnabled = true;
    this.serverConfig.write();
  }

  stopSharing() {
    this.serverConfig.data().metricsEnabled = false;
    this.serverConfig.write();
  }

  isSharingEnabled(): boolean {
    return this.serverConfig.data().metricsEnabled || false;
  }

  private async reportServerUsageMetrics(
    locationUsageMetrics: ReportedUsage[],
    reportEndTimestampMs: number
  ): Promise<void> {
    const userReports: HourlyUserMetricsReportJson[] = [];
    for (const locationUsage of locationUsageMetrics) {
      if (locationUsage.inboundBytes === 0 && locationUsage.tunnelTimeSec === 0) {
        continue;
      }
      // Make sure to always set a country, which is required by the metrics server validation.
      // It's used to differentiate the row from the legacy key usage rows.
      const country = locationUsage.country || 'ZZ';
      const report: HourlyUserMetricsReportJson = {
        countries: [country],
        bytesTransferred: locationUsage.inboundBytes,
        tunnelTimeSec: locationUsage.tunnelTimeSec,
      };
      if (locationUsage.asn) {
        report.asn = locationUsage.asn;
      }
      userReports.push(report);
    }
    const report = {
      serverId: this.serverConfig.data().serverId,
      startUtcMs: this.reportStartTimestampMs,
      endUtcMs: reportEndTimestampMs,
      userReports,
    } as HourlyServerMetricsReportJson;

    if (userReports.length > 0) {
      await this.metricsCollector.collectServerUsageMetrics(report);
    }
    // Keep the reporting window aligned with usageMetrics.reset(). On failure,
    // the next attempt still includes usage since the previous successful report.
    this.reportStartTimestampMs = reportEndTimestampMs;
  }

  private async reportFeatureMetrics(): Promise<void> {
    const keys = this.keyConfig.data().accessKeys;
    const featureMetricsReport = {
      serverId: this.serverConfig.data().serverId,
      serverVersion: version.getPackageVersion(),
      timestampUtcMs: this.clock.now(),
      dataLimit: {
        enabled: !!this.serverConfig.data().accessKeyDataLimit,
        perKeyLimitCount: keys.filter((key) => !!key.dataLimit).length,
      },
    };
    await this.metricsCollector.collectFeatureMetrics(featureMetricsReport);
  }
}
