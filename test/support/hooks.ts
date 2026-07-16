/**
 * Cucumber hooks that run before/after every scenario.
 *
 *  - Before: spin up a Playwright APIRequestContext, GET /login to
 *    harvest the session cookie + CSRF token required by the lab's
 *    Spring Security configuration, then attach them to the World.
 *  - After:  dispose of the request context so the run doesn't leak
 *    file descriptors, and capture scenario status for the final
 *    run-summary.
 */
import { Before, After, Status } from '@cucumber/cucumber';
import { request as pwRequest } from '@playwright/test';
import { LabWorld } from './world';

Before({ tags: 'not @manual-only' }, async function (this: LabWorld) {
  // (Re-)initialise the World. The `this` context for Before is the
  // World instance provided by setWorldConstructor in cucumber.js.
  this.api = await pwRequest.newContext({
    baseURL: this.baseURL,
    extraHTTPHeaders: {
      Accept: 'application/json,text/html,*/*',
    },
    ignoreHTTPSErrors: true,
    timeout: 15000,
  });

  // Hit /login to obtain a JSESSIONID + CSRF token. Spring Security
  // issues a fresh session + a hidden _csrf form field, and embeds the
  // same value in the XSRF-TOKEN cookie when configured with CookieCsrfTokenRepository.
  // The lab uses the default HttpSessionCsrfTokenRepository, so we
  // parse the _csrf value from the rendered login form.
  try {
    const loginPage = await this.api.get('/login');
    const body = await loginPage.text();
    const m = body.match(/name="_csrf"\s+value="([^"]+)"/);
    if (m && m[1]) {
      this.csrfToken = m[1];
    }
  } catch (err) {
    // If /login isn't reachable the first scenario will fail clearly
    // and the test suite will report the cause. Don't crash here.
    this.csrfToken = '';
  }
});

After({ tags: 'not @manual-only' }, async function (this: LabWorld, scenario) {
  this.scenarioStatus =
    scenario.result?.status === Status.PASSED
      ? 'passed'
      : scenario.result?.status === Status.SKIPPED
        ? 'skipped'
        : 'failed';
  if (this.api) {
    await this.api.dispose();
  }
});
