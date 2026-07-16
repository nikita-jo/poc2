/**
 * Playwright configuration shared by the Cucumber World.
 *
 * Cucumber does not pick up playwright.config.ts automatically, but
 * we still want a single source of truth for baseURL, headless mode,
 * and timeouts. The World (support/world.ts) reads from here.
 */
import { defineConfig } from '@playwright/test';

const baseURL = process.env.BASE_URL ?? 'http://localhost:8080';

export default defineConfig({
  use: {
    baseURL,
    headless: true,
    ignoreHTTPSErrors: true,
    actionTimeout: 15000,
    navigationTimeout: 30000,
    trace: 'off',
    screenshot: 'off',
    video: 'off'
  },
  timeout: 60000,
  expect: {
    timeout: 10000
  },
  reporter: 'list'
});
