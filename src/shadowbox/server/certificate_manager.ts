// Copyright 2024 The Outline Authors
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

import * as acme from 'acme-client';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';
import * as tls from 'tls';
import * as logging from '../infrastructure/logging';

// Renew if expiring within 30 days
const RENEW_THRESHOLD_DAYS = 30;
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

export class CertificateManager {
  private client: acme.Client;
  private accountKeyPath: string;

  constructor(
    private readonly hostname: string,
    private readonly certFile: string,
    private readonly keyFile: string,
    private readonly stateDir: string,
    private readonly onUpdate: (context: tls.SecureContext) => void
  ) {
    this.accountKeyPath = path.join(this.stateDir, 'acme-account.key');
  }

  async start() {
    try {
      await this.initClient();
      await this.checkAndRenew();
    } catch (e) {
      logging.error(`CertificateManager initialization failed: ${e}`);
    }

    setInterval(() => {
      this.checkAndRenew().catch((e) => {
        logging.error(`Scheduled certificate renewal failed: ${e}`);
      });
    }, CHECK_INTERVAL_MS);
  }

  private async initClient() {
    let accountKey: Buffer;
    if (fs.existsSync(this.accountKeyPath)) {
      logging.info(`Loading ACME account key from ${this.accountKeyPath}`);
      accountKey = fs.readFileSync(this.accountKeyPath);
    } else {
      logging.info('Generating new ACME account key...');
      accountKey = await acme.crypto.createPrivateKey();
      fs.writeFileSync(this.accountKeyPath, accountKey);
    }

    this.client = new acme.Client({
      directoryUrl: acme.directory.letsencrypt.production,
      accountKey: accountKey,
    });
  }

  private async checkAndRenew() {
    logging.info('Checking certificate status...');
    if (this.shouldRenew()) {
      logging.info('Certificate requires renewal/issuance.');
      await this.renew();
    } else {
      logging.info('Certificate is valid and does not need renewal.');
    }
  }

  private shouldRenew(): boolean {
    if (!fs.existsSync(this.certFile)) {
      logging.warn('Certificate file not found.');
      return true;
    }

    try {
      const certBuffer = fs.readFileSync(this.certFile);
      const cert = new crypto.X509Certificate(certBuffer);

      // Check if self-signed
      if (cert.issuer === cert.subject) {
        logging.info('Current certificate is self-signed.');
        return true;
      }

      // Check expiry
      const validTo = new Date(cert.validTo);
      const now = new Date();
      const daysRemaining = (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

      if (daysRemaining < RENEW_THRESHOLD_DAYS) {
        logging.info(`Certificate expires in ${daysRemaining.toFixed(1)} days.`);
        return true;
      }

      return false;
    } catch (e) {
      logging.error(`Error parsing certificate: ${e}`);
      return true;
    }
  }

  private async renew() {
    logging.info(`Attempting to obtain certificate for ${this.hostname}`);

    // Create a challenge server
    const challengeMap = new Map<string, string>();
    const challengeServer = http.createServer((req, res) => {
      if (req.url && req.url.startsWith('/.well-known/acme-challenge/')) {
        const token = req.url.split('/').pop();
        if (token && challengeMap.has(token)) {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.write(challengeMap.get(token));
          res.end();
          return;
        }
      }
      res.writeHead(404);
      res.end();
    });

    try {
      // Start server on port 80
      await new Promise<void>((resolve, reject) => {
        challengeServer.listen(80, '0.0.0.0', () => {
          logging.info('ACME challenge server listening on port 80');
          resolve();
        });
        challengeServer.on('error', reject);
      });

      // Order certificate
      /* eslint-disable @typescript-eslint/no-explicit-any */
      const order = await this.client.createOrder({
        identifiers: [{ type: 'ip', value: this.hostname }],
      } as any);
      /* eslint-enable @typescript-eslint/no-explicit-any */

      const authorizations = await this.client.getAuthorizations(order);
      const authz = authorizations[0];
      const challenge = authz.challenges.find((c) => c.type === 'http-01');

      if (!challenge) {
        throw new Error('No http-01 challenge found');
      }

      const keyAuthorization = await this.client.getChallengeKeyAuthorization(challenge);

      // Set up the challenge response
      challengeMap.set(challenge.token, keyAuthorization);

      // Verify challenge
      await this.client.completeChallenge(challenge);
      await this.client.waitForValidStatus(challenge);

      // Finalize and download
      const [key, csr] = await acme.crypto.createCsr({
        commonName: this.hostname,
        // IP certificates usually don't need SANs if CN is IP, or maybe they do?
        // Let's Encrypt for IP requires the IP in SANs.
        altNames: [this.hostname],
      });

      const finalize = await this.client.finalizeOrder(order, csr);
      const cert = await this.client.getCertificate(finalize);

      // Save to disk
      logging.info('Certificate obtained successfully. Saving...');
      fs.writeFileSync(this.certFile, cert);
      fs.writeFileSync(this.keyFile, key);

      // Update running server
      const context = tls.createSecureContext({
        cert: cert,
        key: key,
      });
      this.onUpdate(context);
      logging.info('Server security context updated.');

    } catch (e) {
      logging.error(`ACME renewal failed: ${e}`);
      if (e.code === 'EADDRINUSE') {
        logging.error('Port 80 is in use. Cannot perform HTTP-01 challenge.');
      }
      throw e;
    } finally {
      challengeServer.close();
      logging.info('ACME challenge server closed.');
    }
  }
}
