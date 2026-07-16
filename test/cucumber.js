/**
 * Cucumber configuration for the VULN-001 test contract.
 *
 * Scopes to a single feature file (security-validation.feature) and a
 * single step-definition file (security-validation.steps.ts), so we do
 * not pick up unrelated .feature files from other contracts.
 *
 * HTML report is written to test/report.html so the parent agent can
 * upload / surface it.
 *
 * The setWorldConstructor is registered in support/world-bootstrap.ts
 * (loaded as a regular `require`), so cucumber.js itself stays
 * CommonJS-only and doesn't need to import any TS file.
 */
module.exports = {
  default: {
    paths: ['features/**/*.feature'],
    require: [
      'support/world-bootstrap.ts',
      'step-definitions/**/*.ts',
      'support/**/*.ts'
    ],
    requireModule: ['ts-node/register'],
    format: [
      'html:report.html',
      'progress'
    ],
    formatOptions: {
      snippetInterface: 'async-await'
    },
    timeout: 60000,
    parallel: 1
  }
};
