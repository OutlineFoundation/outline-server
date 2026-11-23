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

import {ManualClock} from '../infrastructure/clock';
import {InMemoryConfig} from '../infrastructure/json_config';
import {DataLimit} from '../model/access_key';
import * as version from './version';
import {AccessKeyConfigJson} from './server_access_key';

import {ServerConfigJson} from './server_config';
import {
  ReportedUsage,
  DailyFeatureMetricsReportJson,
  HourlyServerMetricsReportJson,
  MetricsCollectorClient,
  OutlineSharedMetricsPublisher,
  UsageMetrics,
} from './shared_metrics';

describe('OutlineSharedMetricsPublisher', () => {
  describe('Enable/Disable', () => {
    it('Mirrors config', () => {
      const serverConfig = new InMemoryConfig<ServerConfigJson>({});

      const publisher = new OutlineSharedMetricsPublisher(
        new ManualClock(),
        serverConfig,
        null,
        null,
        null
      );
      expect(publisher.isSharingEnabled()).toBeFalsy();

      publisher.startSharing();
      expect(publisher.isSharingEnabled()).toBeTruthy();
      expect(serverConfig.mostRecentWrite.metricsEnabled).toBeTruthy();

      publisher.stopSharing();
      expect(publisher.isSharingEnabled()).toBeFalsy();
      expect(serverConfig.mostRecentWrite.metricsEnabled).toBeFalsy();
    });
    it('Reads from config', () => {
      const serverConfig = new InMemoryConfig<ServerConfigJson>({metricsEnabled: true});
      const publisher = new OutlineSharedMetricsPublisher(
        new ManualClock(),
        serverConfig,
        null,
        null,
        null
      );
      expect(publisher.isSharingEnabled()).toBeTruthy();
    });
  });
  describe('Metrics Reporting', () => {
    it('reports server usage metrics correctly', async () => {
      const clock = new ManualClock();
      let startTime = clock.nowMs;
      const serverConfig = new InMemoryConfig<ServerConfigJson>({serverId: 'server-id'});
      const usageMetrics = new ManualUsageMetrics();
      const metricsCollector = new FakeMetricsCollector();
      const publisher = new OutlineSharedMetricsPublisher(
        clock,
        serverConfig,
        null,
        usageMetrics,
        metricsCollector
      );

      publisher.startSharing();
      usageMetrics.reportedUsage = [
        {country: 'AA', inboundBytes: 11, tunnelTimeSec: 99},
        {country: 'BB', inboundBytes: 11, tunnelTimeSec: 88},
        {country: 'CC', inboundBytes: 22, tunnelTimeSec: 77},
        {country: 'AA', inboundBytes: 33, tunnelTimeSec: 66},
        {country: 'DD', inboundBytes: 33, tunnelTimeSec: 55},
      ];

      clock.nowMs += 60 * 60 * 1000;
      await clock.runCallbacks();
      expect(metricsCollector.collectedServerUsageReport).toEqual({
        serverId: 'server-id',
        startUtcMs: startTime,
        endUtcMs: clock.nowMs,
        userReports: [
          {bytesTransferred: 11, countries: ['AA'], tunnelTimeSec: 99},
          {bytesTransferred: 11, countries: ['BB'], tunnelTimeSec: 88},
          {bytesTransferred: 22, countries: ['CC'], tunnelTimeSec: 77},
          {bytesTransferred: 33, countries: ['AA'], tunnelTimeSec: 66},
          {bytesTransferred: 33, countries: ['DD'], tunnelTimeSec: 55},
        ],
      });

      startTime = clock.nowMs;
      usageMetrics.reportedUsage = [
        {country: 'EE', inboundBytes: 44, tunnelTimeSec: 11},
        {country: 'SY', inboundBytes: 55, tunnelTimeSec: 22},
        {country: 'FF', inboundBytes: 66, tunnelTimeSec: 33},
      ];

      clock.nowMs += 60 * 60 * 1000;
      await clock.runCallbacks();
      expect(metricsCollector.collectedServerUsageReport).toEqual({
        serverId: 'server-id',
        startUtcMs: startTime,
        endUtcMs: clock.nowMs,
        userReports: [
          {bytesTransferred: 44, countries: ['EE'], tunnelTimeSec: 11},
          {bytesTransferred: 55, countries: ['SY'], tunnelTimeSec: 22},
          {bytesTransferred: 66, countries: ['FF'], tunnelTimeSec: 33},
        ],
      });

      publisher.stopSharing();
    });

    it('does not overlap usage reports', async () => {
      const clock = new ManualClock();
      const serverConfig = new InMemoryConfig<ServerConfigJson>({serverId: 'server-id'});
      const usageMetrics = new ManualUsageMetrics();
      usageMetrics.reportedUsage = [{country: 'AA', inboundBytes: 1, tunnelTimeSec: 1}];
      const metricsCollector = new FakeMetricsCollector();
      let finishUpload: () => void = () => {};
      const upload = new Promise<void>((resolve) => {
        finishUpload = resolve;
      });
      spyOn(metricsCollector, 'collectServerUsageMetrics').and.returnValue(upload);
      const publisher = new OutlineSharedMetricsPublisher(
        clock,
        serverConfig,
        null,
        usageMetrics,
        metricsCollector
      );
      publisher.startSharing();

      const firstRun = clock.runCallbacks();
      await Promise.resolve();
      const secondRun = clock.runCallbacks();
      await Promise.resolve();

      expect(metricsCollector.collectServerUsageMetrics).toHaveBeenCalledTimes(1);

      finishUpload();
      await Promise.all([firstRun, secondRun]);
    });

    it('reports ASN metrics correctly', async () => {
      const clock = new ManualClock();
      const serverConfig = new InMemoryConfig<ServerConfigJson>({serverId: 'server-id'});
      const usageMetrics = new ManualUsageMetrics();
      const metricsCollector = new FakeMetricsCollector();
      const publisher = new OutlineSharedMetricsPublisher(
        clock,
        serverConfig,
        null,
        usageMetrics,
        metricsCollector
      );
      publisher.startSharing();

      usageMetrics.reportedUsage = [
        {country: 'DD', inboundBytes: 44, tunnelTimeSec: 11, asn: 999},
        {country: 'EE', inboundBytes: 55, tunnelTimeSec: 22},
      ];
      clock.nowMs += 60 * 60 * 1000;
      await clock.runCallbacks();

      expect(metricsCollector.collectedServerUsageReport.userReports).toEqual([
        {bytesTransferred: 44, tunnelTimeSec: 11, countries: ['DD'], asn: 999},
        {bytesTransferred: 55, tunnelTimeSec: 22, countries: ['EE']},
      ]);
      publisher.stopSharing();
    });

    it('reports different ASNs in the same country correctly', async () => {
      const clock = new ManualClock();
      const serverConfig = new InMemoryConfig<ServerConfigJson>({serverId: 'server-id'});
      const usageMetrics = new ManualUsageMetrics();
      const metricsCollector = new FakeMetricsCollector();
      const publisher = new OutlineSharedMetricsPublisher(
        clock,
        serverConfig,
        null,
        usageMetrics,
        metricsCollector
      );
      publisher.startSharing();

      usageMetrics.reportedUsage = [
        {country: 'DD', asn: 999, tunnelTimeSec: 11, inboundBytes: 44},
        {country: 'DD', asn: 888, tunnelTimeSec: 22, inboundBytes: 55},
      ];
      clock.nowMs += 60 * 60 * 1000;
      await clock.runCallbacks();

      expect(metricsCollector.collectedServerUsageReport.userReports).toEqual([
        {bytesTransferred: 44, tunnelTimeSec: 11, countries: ['DD'], asn: 999},
        {bytesTransferred: 55, tunnelTimeSec: 22, countries: ['DD'], asn: 888},
      ]);
      publisher.stopSharing();
    });

    it('reports the same ASNs across different countries correctly', async () => {
      const clock = new ManualClock();
      const serverConfig = new InMemoryConfig<ServerConfigJson>({serverId: 'server-id'});
      const usageMetrics = new ManualUsageMetrics();
      const metricsCollector = new FakeMetricsCollector();
      const publisher = new OutlineSharedMetricsPublisher(
        clock,
        serverConfig,
        null,
        usageMetrics,
        metricsCollector
      );
      publisher.startSharing();

      usageMetrics.reportedUsage = [
        {country: 'DD', asn: 999, tunnelTimeSec: 11, inboundBytes: 44},
        {country: 'EE', asn: 999, tunnelTimeSec: 22, inboundBytes: 55},
      ];
      clock.nowMs += 60 * 60 * 1000;
      await clock.runCallbacks();

      expect(metricsCollector.collectedServerUsageReport.userReports).toEqual([
        {bytesTransferred: 44, tunnelTimeSec: 11, countries: ['DD'], asn: 999},
        {bytesTransferred: 55, tunnelTimeSec: 22, countries: ['EE'], asn: 999},
      ]);
      publisher.stopSharing();
    });
  });
  it('reports feature metrics correctly', async () => {
    const clock = new ManualClock();
    let timestamp = clock.nowMs;
    const serverConfig = new InMemoryConfig<ServerConfigJson>({
      serverId: 'server-id',
      accessKeyDataLimit: {bytes: 123},
    });
    let keyId = 0;
    const makeKeyJson = (dataLimit?: DataLimit) => {
      return {
        id: (keyId++).toString(),
        name: 'name',
        password: 'pass',
        port: 12345,
        dataLimit,
      };
    };
    const keyConfig = new InMemoryConfig<AccessKeyConfigJson>({
      accessKeys: [makeKeyJson({bytes: 2}), makeKeyJson()],
    });
    const metricsCollector = new FakeMetricsCollector();
    const publisher = new OutlineSharedMetricsPublisher(
      clock,
      serverConfig,
      keyConfig,
      new ManualUsageMetrics(),
      metricsCollector
    );

    publisher.startSharing();
    await clock.runCallbacks();
    expect(metricsCollector.collectedFeatureMetricsReport).toEqual({
      serverId: 'server-id',
      serverVersion: version.getPackageVersion(),
      timestampUtcMs: timestamp,
      dataLimit: {
        enabled: true,
        perKeyLimitCount: 1,
      },
    });
    clock.nowMs += 24 * 60 * 60 * 1000;
    timestamp = clock.nowMs;

    delete serverConfig.data().accessKeyDataLimit;
    await clock.runCallbacks();
    expect(metricsCollector.collectedFeatureMetricsReport).toEqual({
      serverId: 'server-id',
      serverVersion: version.getPackageVersion(),
      timestampUtcMs: timestamp,
      dataLimit: {
        enabled: false,
        perKeyLimitCount: 1,
      },
    });

    clock.nowMs += 24 * 60 * 60 * 1000;
    delete keyConfig.data().accessKeys[0].dataLimit;
    await clock.runCallbacks();
    expect(metricsCollector.collectedFeatureMetricsReport.dataLimit.perKeyLimitCount).toEqual(0);
  });
  it('does not report metrics when sharing is disabled', async () => {
    const clock = new ManualClock();
    const serverConfig = new InMemoryConfig<ServerConfigJson>({
      serverId: 'server-id',
      metricsEnabled: false,
    });
    const metricsCollector = new FakeMetricsCollector();
    spyOn(metricsCollector, 'collectServerUsageMetrics').and.callThrough();
    spyOn(metricsCollector, 'collectFeatureMetrics').and.callThrough();
    new OutlineSharedMetricsPublisher(
      clock,
      serverConfig,
      new InMemoryConfig<AccessKeyConfigJson>({}),
      new ManualUsageMetrics(),
      metricsCollector
    );

    await clock.runCallbacks();
    expect(metricsCollector.collectServerUsageMetrics).not.toHaveBeenCalled();
    expect(metricsCollector.collectFeatureMetrics).not.toHaveBeenCalled();
  });
});

class FakeMetricsCollector implements MetricsCollectorClient {
  collectedServerUsageReport: HourlyServerMetricsReportJson;
  collectedFeatureMetricsReport: DailyFeatureMetricsReportJson;

  async collectServerUsageMetrics(report) {
    this.collectedServerUsageReport = report;
  }

  async collectFeatureMetrics(report) {
    this.collectedFeatureMetricsReport = report;
  }
}

class ManualUsageMetrics implements UsageMetrics {
  reportedUsage = [] as ReportedUsage[];

  getReportedUsage(): Promise<ReportedUsage[]> {
    return Promise.resolve(this.reportedUsage);
  }

  reset() {
    this.reportedUsage = [] as ReportedUsage[];
  }
}
