/**
 * Step definitions for the VULN-001 security validation suite.
 *
 *  - Scenarios tagged @TC-VULN-001-001 cover the deserialization
 *    gadget-chain rejection contract (CWE-502) on POST /api/deserialize.
 *  - Scenarios tagged @TC-VULN-001-002 cover the reflected XSS escaping
 *    contract (CWE-79) on GET /api/comment/greet.
 *
 * Step text is intentionally verbose so the Cucumber HTML report shows
 * a meaningful sentence rather than terse imperative verbs. Endpoint
 * paths contain slashes, so we use RegExp matching instead of the
 * default CucumberExpression (which treats `/` as alternation).
 */
import { Given, When, Then } from '@cucumber/cucumber';
import { expect } from '@playwright/test';
import { LabWorld } from '../support/world';
import {
  assertBodyContains,
  assertBodyDoesNotContain,
  assertStatusEquals,
  getGreet,
  postSerializedPayload,
} from '../support/helpers';

// =====================================================================
// Background steps
// =====================================================================

Given(
  /^the OWASP lab application is reachable on http:\/\/localhost:8080$/,
  async function (this: LabWorld) {
    const probe = await this.api.get('/api/comment/greet', {
      headers: { Accept: 'text/html' },
    });
    // The endpoint requires auth; any HTTP response (200 or 401) proves
    // the server is alive. 200 means the basic auth header worked.
    if (probe.status() !== 200 && probe.status() !== 401) {
      throw new Error(
        `Lab application did not respond on ${this.baseURL}: status=${probe.status()}`
      );
    }
  }
);

Given('a registered test user is authenticated via HTTP Basic', function (this: LabWorld) {
  // The HTTP Basic header is pre-built on the World and applied to every
  // request via the APIRequestContext `extraHTTPHeaders`. The Before hook
  // also captured a JSESSIONID + CSRF token from /login for state-changing
  // POSTs.
  expect(this.basicAuthHeader.startsWith('Basic ')).toBe(true);
  expect(this.csrfToken.length).toBeGreaterThan(0);
});

// =====================================================================
// TC-VULN-001-001 — Deserialization
// =====================================================================

Given('a Base64-encoded Java serialised HashMap', function (this: LabWorld) {
  // The pre-built benign HashMap payload (java.util.*) lives on the World.
  expect(this.benignHashMapBase64).toMatch(/^rO0ABXN/);
});

Given(
  'a Base64-encoded Java serialised InvokerTransformer gadget payload',
  function (this: LabWorld) {
    expect(this.gadgetInvokerTransformerBase64).toMatch(/^rO0ABXN/);
  }
);

Given(
  'a Base64-encoded Java serialised Spring ObjectFactory gadget payload',
  function (this: LabWorld) {
    expect(this.gadgetSpringObjectFactoryBase64).toMatch(/^rO0ABXN/);
  }
);

Given(
  'a Base64-encoded Java serialised GroovyObject gadget payload',
  function (this: LabWorld) {
    expect(this.gadgetGroovyObjectBase64).toMatch(/^rO0ABXN/);
  }
);

Given(
  /^the client POSTs the benign payload to \/api\/deserialize$/,
  async function (this: LabWorld) {
    // The remediated controller parses JSON (Jackson) instead of doing
    // native Java deserialisation. The "positive" path therefore
    // requires a well-formed JSON object. The legacy Class-allowlist
    // (com.owasp.lab.model.*, java.util.HashMap, ...) has been
    // replaced by Jackson's fail-on-unknown-properties policy.
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Authorization: this.basicAuthHeader,
    };
    if (this.csrfToken) {
      headers['X-CSRF-TOKEN'] = this.csrfToken;
    }
    this.lastResponse = await this.api.post('/api/deserialize', {
      headers,
      data: '{"id":1,"name":"alice-product","description":"16GB RAM","price":1299.99}',
    });
  }
);

Given(
  /^the client POSTs the InvokerTransformer gadget payload to \/api\/deserialize$/,
  async function (this: LabWorld) {
    this.lastResponse = await postSerializedPayload(
      this,
      this.gadgetInvokerTransformerBase64,
      'application/octet-stream'
    );
  }
);

Given(
  /^the client POSTs the Spring ObjectFactory gadget payload to \/api\/deserialize$/,
  async function (this: LabWorld) {
    this.lastResponse = await postSerializedPayload(
      this,
      this.gadgetSpringObjectFactoryBase64,
      'application/octet-stream'
    );
  }
);

Given(
  /^the client POSTs the GroovyObject gadget payload to \/api\/deserialize$/,
  async function (this: LabWorld) {
    this.lastResponse = await postSerializedPayload(
      this,
      this.gadgetGroovyObjectBase64,
      'application/octet-stream'
    );
  }
);

Then('the response status is 200', async function (this: LabWorld) {
  assertStatusEquals(this.lastResponse!, 200, 'greet/deserialize positive case');
});

Then('the response status is NOT 200', async function (this: LabWorld) {
  const status = this.lastResponse!.status();
  if (status === 200) {
    throw new Error(
      `Gadget payload was accepted (status 200)! Body: ${await this.lastResponse!.text()}`
    );
  }
  // Acceptable: 400, 415, 422, 500 — anything but 200.
  if (![400, 401, 403, 404, 415, 422, 500].includes(status)) {
    throw new Error(`Unexpected reject status ${status}`);
  }
});

Then('the response body identifies a parsed Map type', async function (this: LabWorld) {
  const body = await this.lastResponse!.text();
  assertBodyContains(body, 'Map<String,Object>', 'deserialize positive case');
});

Then(
  'the response body does not contain {string}',
  async function (this: LabWorld, needle: string) {
    const body = await this.lastResponse!.text();
    assertBodyDoesNotContain(body, needle, 'deserialize reject case');
  }
);

Then(
  'the response body contains {string}',
  async function (this: LabWorld, needle: string) {
    const body = await this.lastResponse!.text();
    assertBodyContains(body, needle, 'greet positive case');
  }
);

// =====================================================================
// TC-VULN-001-002 — Reflected XSS
// =====================================================================

Given(
  /^the user issues GET \/api\/comment\/greet\?name=Alice$/,
  async function (this: LabWorld) {
    this.lastResponse = await getGreet(this, 'Alice');
  }
);

Given(
  /^the user issues GET \/api\/comment\/greet with name "(.*)"$/,
  async function (this: LabWorld, name: string) {
    this.lastResponse = await getGreet(this, name);
  }
);

Given(
  /^the user issues GET \/api\/comment\/greet with no name parameter$/,
  async function (this: LabWorld) {
    this.lastResponse = await this.api.get('/api/comment/greet', {
      headers: {
        Authorization: this.basicAuthHeader,
        Accept: 'text/html',
      },
    });
  }
);

Then(
  /^the response Content-Type is text\/html$/,
  async function (this: LabWorld) {
    const ct = this.lastResponse!.headers()['content-type'] ?? '';
    if (!ct.toLowerCase().includes('text/html')) {
      throw new Error(`Expected text/html Content-Type, got: ${ct}`);
    }
  }
);

Then(
  'the response body contains the entity-encoded {string} token',
  async function (this: LabWorld, raw: string) {
    const body = await this.lastResponse!.text();
    // Spring's HtmlUtils.htmlEscape encodes "<" as &lt; and ">" as &gt;.
    const escaped = raw
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
    assertBodyContains(body, escaped, 'XSS escape check');
  }
);

Then(
  'the response body does not contain the raw {string} substring',
  async function (this: LabWorld, raw: string) {
    const body = await this.lastResponse!.text();
    assertBodyDoesNotContain(body, raw, 'XSS raw-token check');
  }
);
