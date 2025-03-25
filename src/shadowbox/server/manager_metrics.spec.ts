// Copyright 2019 The Outline Authors
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

import {PrometheusManagerMetrics} from './manager_metrics';
import {PrometheusClient, QueryResultData} from '../infrastructure/prometheus_scraper';
import {FakePrometheusClient} from './mocks/mocks';

export class QueryMapPrometheusClient implements PrometheusClient {
  constructor(
    private queryMap: {[query: string]: QueryResultData},
    private queryRangeMap: {[query: string]: QueryResultData}
  ) {}

  async query(query: string): Promise<QueryResultData> {
    return this.queryMap[query];
  }

  async queryRange(
    query: string,
    _start: number,
    _end: number,
    _step: string
  ): Promise<QueryResultData> {
    return this.queryRangeMap[query];
  }
}

describe('PrometheusManagerMetrics', () => {
  it('getServerMetrics', async (done) => {
    const managerMetrics = new PrometheusManagerMetrics(
      new QueryMapPrometheusClient(
        {
          'sum(increase(shadowsocks_tunnel_time_seconds_per_location[0s])) by (location, asn, asorg)':
            {
              resultType: 'vector',
              result: [
                {
                  metric: {
                    location: 'US',
                    asn: '49490',
                    asorg: 'Test AS Org',
                  },
                  value: [1738959398, '1000'],
                },
              ],
            },
        },
        {
          'sum(increase(shadowsocks_data_bytes_per_location{dir=~"c<p|p>t"}[300s])) by (location, asn, asorg)':
            {
              resultType: 'matrix',
              result: [
                {
                  metric: {
                    location: 'US',
                    asn: '49490',
                    asorg: 'Test AS Org',
                  },
                  values: [
                    [1738959398, '9000'],
                    [1739284734, '3000'],
                  ],
                },
              ],
            },
          'sum(increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[300s])) by (access_key)': {
            resultType: 'matrix',
            result: [
              {
                metric: {
                  access_key: '0',
                },
                values: [
                  [1738959398, '9000'],
                  [1739284734, '3000'],
                ],
              },
            ],
          },
          'sum(increase(shadowsocks_tunnel_time_seconds[300s])) by (access_key)': {
            resultType: 'matrix',
            result: [
              {
                metric: {
                  access_key: '0',
                },
                values: [
                  [1738959398, '1000'],
                  [1738959398, '0'],
                ],
              },
            ],
          },
        }
      )
    );

    const serverMetrics = await managerMetrics.getServerMetrics({seconds: 0});

    expect(JSON.stringify(serverMetrics, null, 2)).toEqual(`{
  "server": {
    "tunnelTime": {
      "seconds": 1000
    },
    "dataTransferred": {
      "bytes": 12000
    },
    "bandwidth": {
      "current": {
        "data": {
          "bytes": 10
        },
        "timestamp": 1739284734
      },
      "peak": {
        "data": {
          "bytes": 30
        },
        "timestamp": 1738959398
      }
    },
    "locations": [
      {
        "location": "US",
        "asn": 49490,
        "asOrg": "Test AS Org",
        "dataTransferred": {
          "bytes": 12000
        },
        "tunnelTime": {
          "seconds": 1000
        }
      }
    ]
  },
  "accessKeys": [
    {
      "accessKeyId": 0,
      "dataTransferred": {
        "bytes": 12000
      },
      "tunnelTime": {
        "seconds": 1000
      },
      "connection": {
        "lastTrafficSeen": 1739284734,
        "peakDeviceCount": {
          "data": 4,
          "timestamp": 1738959398
        }
      }
    }
  ]
}`);
    done();
  });

  it('getServerMetrics - combines sources', async (done) => {
    const managerMetrics = new PrometheusManagerMetrics(
      new QueryMapPrometheusClient(
        {
          'sum(increase(shadowsocks_tunnel_time_seconds_per_location[0s])) by (location, asn, asorg)':
            {
              resultType: 'vector',
              result: [
                {
                  metric: {
                    location: 'US',
                    asn: '49490',
                    asorg: 'Test AS Org',
                  },
                  value: [1738959398, '1000'],
                },
              ],
            },
        },
        {
          'sum(increase(shadowsocks_data_bytes_per_location{dir=~"c<p|p>t"}[300s])) by (location, asn, asorg)':
            {
              resultType: 'matrix',
              result: [
                {
                  metric: {
                    location: 'CA',
                  },
                  values: [
                    [1738959398, '9000'],
                    [1739284734, '3000'],
                  ],
                },
              ],
            },
          'sum(increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[300s])) by (access_key)': {
            resultType: 'matrix',
            result: [
              {
                metric: {
                  access_key: '0',
                },
                values: [
                  [1738959398, '9000'],
                  [1739284734, '3000'],
                ],
              },
            ],
          },
          'sum(increase(shadowsocks_tunnel_time_seconds[300s])) by (access_key)': {
            resultType: 'matrix',
            result: [
              {
                metric: {
                  access_key: '1',
                },
                values: [
                  [1738959398, '1000'],
                  [1738959398, '0'],
                ],
              },
            ],
          },
        }
      )
    );

    const serverMetrics = await managerMetrics.getServerMetrics({seconds: 0});

    expect(JSON.stringify(serverMetrics, null, 2)).toEqual(`{
  "server": {
    "tunnelTime": {
      "seconds": 1000
    },
    "dataTransferred": {
      "bytes": 12000
    },
    "bandwidth": {
      "current": {
        "data": {
          "bytes": 10
        },
        "timestamp": 1739284734
      },
      "peak": {
        "data": {
          "bytes": 30
        },
        "timestamp": 1738959398
      }
    },
    "locations": [
      {
        "location": "CA",
        "asn": null,
        "asOrg": null,
        "dataTransferred": {
          "bytes": 12000
        },
        "tunnelTime": {
          "seconds": 0
        }
      },
      {
        "location": "US",
        "asn": 49490,
        "asOrg": "Test AS Org",
        "dataTransferred": {
          "bytes": 0
        },
        "tunnelTime": {
          "seconds": 1000
        }
      }
    ]
  },
  "accessKeys": [
    {
      "accessKeyId": 0,
      "dataTransferred": {
        "bytes": 12000
      },
      "tunnelTime": {
        "seconds": 0
      },
      "connection": {
        "lastTrafficSeen": 1739284734,
        "peakDeviceCount": {
          "data": 0,
          "timestamp": null
        }
      }
    },
    {
      "accessKeyId": 1,
      "dataTransferred": {
        "bytes": 0
      },
      "tunnelTime": {
        "seconds": 1000
      },
      "connection": {
        "lastTrafficSeen": null,
        "peakDeviceCount": {
          "data": 4,
          "timestamp": 1738959398
        }
      }
    }
  ]
}`);
    done();
  });

  it('getOutboundByteTransfer', async (done) => {
    const managerMetrics = new PrometheusManagerMetrics(
      new FakePrometheusClient({'access-key-1': 1000, 'access-key-2': 10000})
    );
    const dataUsage = await managerMetrics.getOutboundByteTransfer({hours: 0});
    const bytesTransferredByUserId = dataUsage.bytesTransferredByUserId;
    expect(Object.keys(bytesTransferredByUserId).length).toEqual(2);
    expect(bytesTransferredByUserId['access-key-1']).toEqual(1000);
    expect(bytesTransferredByUserId['access-key-2']).toEqual(10000);
    done();
  });
});
