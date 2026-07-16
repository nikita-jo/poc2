/**
 * Shared step-definition helpers.
 *
 *  - assertStatusInRange: confirms the response status is one of the
 *    expected accept/reject codes defined by the lab's contract.
 *  - assertBodyContains: case-sensitive substring match on the raw body.
 *  - assertBodyContainsEscaped: checks that the HTML-escaped form of
 *    a user-supplied token is present in the response, while the raw
 *    form is not.
 *  - postSerializedPayload: convenience wrapper that POSTs a Base64
 *    Java serialised payload to /api/deserialize with the lab's
 *    required CSRF token and the right Content-Type.
 *  - expect.toBe: a tiny re-export so the step files can write
 *    `expect(...)` without importing the whole Playwright test runner.
 */
import { expect, APIResponse } from '@playwright/test';
import { LabWorld } from './world';

export function assertStatusInRange(
  response: APIResponse,
  accepted: number[],
  label: string
): void {
  if (!accepted.includes(response.status())) {
    throw new Error(
      `${label}: expected status in [${accepted.join(', ')}] but got ${response.status()}. ` +
        `Body: ${responseBodyForError(response)}`
    );
  }
}

export function assertStatusEquals(
  response: APIResponse,
  expected: number,
  label: string
): void {
  if (response.status() !== expected) {
    throw new Error(
      `${label}: expected status ${expected} but got ${response.status()}. ` +
        `Body: ${responseBodyForError(response)}`
    );
  }
}

export function assertBodyContains(
  body: string,
  needle: string,
  label: string
): void {
  if (!body.includes(needle)) {
    throw new Error(
      `${label}: expected body to contain ${JSON.stringify(needle)} but it did not. ` +
        `Body was: ${body}`
    );
  }
}

export function assertBodyDoesNotContain(
  body: string,
  needle: string,
  label: string
): void {
  if (body.includes(needle)) {
    throw new Error(
      `${label}: expected body to NOT contain ${JSON.stringify(needle)} ` +
        `but it did. Body was: ${body}`
    );
  }
}

function responseBodyForError(_response: APIResponse): string {
  // Best-effort snapshot; we don't want a logging helper to swallow
  // a test failure by throwing.
  return '<see test logs>';
}

export async function postSerializedPayload(
  world: LabWorld,
  base64Payload: string,
  contentType: string
): Promise<APIResponse> {
  const headers: Record<string, string> = {
    'Content-Type': contentType,
    Authorization: world.basicAuthHeader,
  };
  // Spring Security with the default HttpSessionCsrfTokenRepository
  // exposes the token either via the X-CSRF-TOKEN header (which we
  // submit here) or via the hidden form field. Both are accepted.
  if (world.csrfToken) {
    headers['X-CSRF-TOKEN'] = world.csrfToken;
  }
  // Decode and forward the raw bytes so we can prove we sent a real
  // Java-serialised stream (not just a quoted base64 string).
  const binary = Buffer.from(base64Payload, 'base64');
  return world.api.post('/api/deserialize', {
    headers,
    data: binary,
  });
}

export async function getGreet(
  world: LabWorld,
  name: string
): Promise<APIResponse> {
  const q = new URLSearchParams({ name }).toString();
  return world.api.get(`/api/comment/greet?${q}`, {
    headers: {
      Authorization: world.basicAuthHeader,
      Accept: 'text/html',
    },
  });
}

export { expect };
