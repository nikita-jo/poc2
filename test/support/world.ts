/**
 * Custom Cucumber World shared by every scenario.
 *
 * The World holds:
 *  - a Playwright APIRequestContext (so step definitions don't have to
 *    spin up a new context for every HTTP call);
 *  - the base URL (read from playwright.config.ts / BASE_URL env var);
 *  - the HTTP Basic credentials that satisfy the lab's session/Cookie
 *    CSRF requirement on POST /api/* endpoints;
 *  - the last API response so steps can assert on it;
 *  - CSRF cookie + token captured from /login, required by the lab's
 *    Spring Security configuration for state-changing requests.
 */
import { World, IWorldOptions } from '@cucumber/cucumber';
import { APIRequestContext, APIResponse, request as pwRequest } from '@playwright/test';

export class LabWorld extends World {
  public baseURL: string;
  public api!: APIRequestContext;
  public lastResponse: APIResponse | null;
  public csrfCookie: string;
  public csrfToken: string;
  public basicAuthHeader: string;
  public username: string;
  public password: string;
  // Reusable Java-serialised Base64 payloads (see helpers.ts).
  public benignHashMapBase64: string;
  public gadgetInvokerTransformerBase64: string;
  public gadgetSpringObjectFactoryBase64: string;
  public gadgetGroovyObjectBase64: string;
  // Track which tests have been seen for the run-summary.
  public scenarioStatus: 'passed' | 'failed' | 'skipped' | 'pending';

  constructor(options: IWorldOptions) {
    super(options);
    this.baseURL = process.env.BASE_URL ?? 'http://localhost:8080';
    this.username = process.env.LAB_USER ?? 'alice';
    this.password = process.env.LAB_PASS ?? 'alice123';
    this.basicAuthHeader =
      'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64');
    this.lastResponse = null;
    this.csrfCookie = '';
    this.csrfToken = '';
    this.benignHashMapBase64 =
      'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAACdAAEcm9sZXQABFVTRVJ0AAR1c2VydAAFYWxpY2V4';
    this.gadgetInvokerTransformerBase64 =
      'rO0ABXNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyAAAAAAAAAAACAAB4cA==';
    this.gadgetSpringObjectFactoryBase64 =
      'rO0ABXNyAC9vcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3RvcnkuT2JqZWN0RmFjdG9yeQAAAAAAAAAAAgAAeHA=';
    this.gadgetGroovyObjectBase64 =
      'rO0ABXNyABhncm9vdnkubGFuZy5Hcm9vdnlPYmplY3QAAAAAAAAAAAIAAHhw';
    this.scenarioStatus = 'pending';
  }
}
