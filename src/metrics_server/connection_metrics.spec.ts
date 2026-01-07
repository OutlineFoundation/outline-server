// Copyright 2020 The Outline Authors
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
  ConnectionRow,
  isValidConnectionMetricsReport,
  postConnectionMetrics,
} from './connection_metrics';
import {InsertableTable} from './infrastructure/table';
import {HourlyConnectionMetricsReport, HourlyUserConnectionMetricsReport} from './model';

const VALID_USER_REPORT: HourlyUserConnectionMetricsReport = {
  countries: ['US'],
  bytesTransferred: 123,
  tunnelTimeSec: 789,
};

const VALID_USER_REPORT2: HourlyUserConnectionMetricsReport = {
  countries: ['UK'],
  asn: 54321,
  bytesTransferred: 456,
};

/*
 * Legacy access key user reports to ensure backwards compatibility with servers not
 * synced past https://github.com/OutlineFoundation/outline-server/pull/1529).
 */
const LEGACY_PER_KEY_USER_REPORT: HourlyUserConnectionMetricsReport = {
  userId: 'foo',
  bytesTransferred: 123,
};

/*
 * Legacy multiple countries user reports to ensure backwards compatibility with servers
 * not synced past https://github.com/OutlineFoundation/outline-server/pull/1242.
 */
const LEGACY_PER_LOCATION_USER_REPORT: HourlyUserConnectionMetricsReport = {
  userId: 'foobar',
  countries: ['US', 'UK'],
  bytesTransferred: 123,
};

const VALID_REPORT: HourlyConnectionMetricsReport = {
  serverId: 'id',
  startUtcMs: 1,
  endUtcMs: 2,
  userReports: [
    structuredClone(VALID_USER_REPORT),
    structuredClone(VALID_USER_REPORT2),
    structuredClone(LEGACY_PER_LOCATION_USER_REPORT),
  ],
};

const LEGACY_REPORT: HourlyConnectionMetricsReport = {
  serverId: 'legacy-id',
  startUtcMs: 3,
  endUtcMs: 4,
  userReports: [structuredClone(LEGACY_PER_KEY_USER_REPORT)],
};

class FakeConnectionsTable implements InsertableTable<ConnectionRow> {
  rows: ConnectionRow[] | undefined;

  async insert(rows: ConnectionRow[]) {
    this.rows = rows;
  }
}

describe('postConnectionMetrics', () => {
  it('correctly inserts connection metrics rows', async () => {
    const table = new FakeConnectionsTable();

    await postConnectionMetrics(table, VALID_REPORT);

    const rows: ConnectionRow[] = [
      {
        serverId: VALID_REPORT.serverId,
        startTimestamp: new Date(VALID_REPORT.startUtcMs).toISOString(),
        endTimestamp: new Date(VALID_REPORT.endUtcMs).toISOString(),
        bytesTransferred: VALID_USER_REPORT.bytesTransferred,
        tunnelTimeSec: VALID_USER_REPORT.tunnelTimeSec,
        countries: VALID_USER_REPORT.countries,
        asn: undefined,
      },
      {
        serverId: VALID_REPORT.serverId,
        startTimestamp: new Date(VALID_REPORT.startUtcMs).toISOString(),
        endTimestamp: new Date(VALID_REPORT.endUtcMs).toISOString(),
        bytesTransferred: VALID_USER_REPORT2.bytesTransferred,
        tunnelTimeSec: VALID_USER_REPORT2.tunnelTimeSec,
        countries: VALID_USER_REPORT2.countries,
        asn: VALID_USER_REPORT2.asn!,
      },
      {
        serverId: VALID_REPORT.serverId,
        startTimestamp: new Date(VALID_REPORT.startUtcMs).toISOString(),
        endTimestamp: new Date(VALID_REPORT.endUtcMs).toISOString(),
        bytesTransferred: LEGACY_PER_LOCATION_USER_REPORT.bytesTransferred,
        tunnelTimeSec: LEGACY_PER_LOCATION_USER_REPORT.tunnelTimeSec,
        countries: LEGACY_PER_LOCATION_USER_REPORT.countries,
        asn: undefined,
      },
    ];
    expect(table.rows).toEqual(rows);
  });
  it('correctly drops legacy connection metrics', async () => {
    const table = new FakeConnectionsTable();

    await postConnectionMetrics(table, LEGACY_REPORT);

    expect(table.rows).toEqual([]);
  });
});

describe('isValidConnectionMetricsReport', () => {
  it('returns true for valid report', () => {
    const report = structuredClone(VALID_REPORT);
    expect(isValidConnectionMetricsReport(report)).toBeTrue();
  });
  it('returns true for legacy report', () => {
    const report = structuredClone(LEGACY_REPORT);
    expect(isValidConnectionMetricsReport(report)).toBeTrue();
  });
  it('returns false for missing report', () => {
    expect(isValidConnectionMetricsReport(undefined)).toBeFalse();
  });
  it('returns false for inconsistent timestamp values', () => {
    const report = structuredClone(VALID_REPORT);
    // startUtcMs > endUtcMs
    report.startUtcMs = 999;
    report.endUtcMs = 1;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for out-of-bounds transferred bytes', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].bytesTransferred = -123;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();

    // 2TB is above the server capacity
    report.userReports[0].bytesTransferred = 2 * Math.pow(2, 40);
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for out-of-bounds tunnel time', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].tunnelTimeSec = -123;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for missing user reports', () => {
    const report: Partial<HourlyConnectionMetricsReport> = structuredClone(VALID_REPORT);
    delete report['userReports'];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for empty user reports', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports = [];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for missing `serverId`', () => {
    const report: Partial<HourlyConnectionMetricsReport> = structuredClone(VALID_REPORT);
    delete report['serverId'];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for missing `startUtcMs`', () => {
    const report: Partial<HourlyConnectionMetricsReport> = structuredClone(VALID_REPORT);
    delete report['startUtcMs'];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for missing `endUtcMs`', () => {
    const report: Partial<HourlyConnectionMetricsReport> = structuredClone(VALID_REPORT);
    delete report['endUtcMs'];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for missing user report field `bytesTransferred`', () => {
    const report = structuredClone(VALID_REPORT);
    const userReport: Partial<HourlyUserConnectionMetricsReport> =
      structuredClone(VALID_USER_REPORT);
    delete userReport['bytesTransferred'];
    report.userReports[0] = userReport as HourlyUserConnectionMetricsReport;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for user report field types that is not `HourlyUserConnectionMetricsReport`', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports = [1, 2, 3] as unknown as HourlyUserConnectionMetricsReport[];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `serverId` field type that is not a string', () => {
    const report = structuredClone(VALID_REPORT);
    report.serverId = 987 as unknown as string;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `startUtcMs` field type that is not a number', () => {
    const report = structuredClone(VALID_REPORT);
    report.startUtcMs = '100' as unknown as number;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `endUtcMs` field type that is not a number', () => {
    const report = structuredClone(VALID_REPORT);
    report.endUtcMs = '100' as unknown as number;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `userId` field type that is not a string', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].userId = 1234 as unknown as string;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `countries` field type that is not an array', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].countries = 'US' as unknown as string[];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `countries` array items that are not strings', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].countries = [1, 2, 3] as unknown as string[];
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `asn` field type that is not a number', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].asn = '123' as unknown as number;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `bytesTransferred` field type that is not a number', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].bytesTransferred = '1234' as unknown as number;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
  it('returns false for `tunnelTimeSec` field type that is not a number', () => {
    const report = structuredClone(VALID_REPORT);
    report.userReports[0].tunnelTimeSec = '789' as unknown as number;
    expect(isValidConnectionMetricsReport(report)).toBeFalse();
  });
});
