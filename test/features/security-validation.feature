@security-validation
Feature: Security validation from manual test contract

  The scenarios in this file are generated from
  `manualtestJSON/vulntestcase.json`. Each scenario exercises one manual
  security test case against the running OWASP lab application on
  `http://localhost:8080`.

  Background:
    Given the OWASP lab application is reachable on http://localhost:8080

  # Agent contract: You are an elite QA Automation Engineer -- an autonomous agent specialized in transforming manual test specifications into production-grade end-to-end automation suites. You are an expert in Playwrigh

  @security @severity-CRITICAL @CWE_502 @id-TC_VULN_001_001
  Scenario: [TC-VULN-001-001] Verify that the /api/deserialize endpoint rejects gadget-chain deserialisation payloads (ObjectInputFilter whitelisting) (POST /api/deserialize)
    Given Generate a Java serialised object for a whitelisted class (com.owasp.lab.model.*) using a benign DTO, then Base64-encode it.
    When Send a POST request to /api/deserialize with the Base64 payload in the request body (Content-Type: application/octet-stream or text/plain depending on the controller binding).
    Then Confirm the server responds with HTTP 200 and the deserialised object is processed (positive baseline).
    When Generate a Java serialised object for a non-whitelisted gadget class (e.g. org.apache.commons.collections.functors.InvokerTransformer) using ysoserial, then Base64-encode it.
    When Send a POST request to /api/deserialize with the gadget payload.
    Then Observe the response: it MUST be rejected (HTTP 400, 422 or 500 with an InvalidClassException) and MUST NOT execute any constructor or static initialiser of the gadget class.
    Then Repeat steps 4-6 with at least one additional non-whitelisted class (e.g. a spring-core or groovy gadget) to confirm the filter is class-agnostic.
    Then Verify the server logs do NOT contain evidence of a ClassNotFoundException bypass or filter bypass.

  @security @severity-HIGH @CWE_79 @id-TC_VULN_001_002
  Scenario: [TC-VULN-001-002] Verify that /api/comment/greet HTML-escapes the 'name' query parameter to prevent reflected XSS (GET /api/comment/greet)
    Given Send GET /api/comment/greet?name=Alice and confirm the response body contains 'Hello, Alice!' (positive baseline).
    When Send GET /api/comment/greet?name=<script>alert('XSS')</script> (URL-encoded as needed).
    Then Inspect the raw response body and confirm the literal characters '&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;' (or equivalent entity-encoded form) are present and that the raw characters '<script>' and '</script>' do NOT appear i...
    Then Send GET /api/comment/greet?name=<img src=x onerror=alert(1)> and confirm the response contains '&lt;img src=x onerror=alert(1)&gt;' (or equivalent entity-encoded form) and the raw '<img' tag does NOT appear.
    Then Send GET /api/comment/greet?name="><svg/onload=alert(1)> and confirm the response contains the entity-encoded form ('&quot;&gt;&lt;svg/onload=alert(1)&gt;' or equivalent) and the raw characters '"' followed by '>' are not present un-esca...
    Then Render the response in a real browser and confirm no JavaScript alert/dialog fires.
    Then Send GET /api/comment/greet with no name parameter and confirm the response defaults to 'Hello, World!' (regression check for null handling).
    Then Check the response Content-Type header is text/html and not reflected into an executable context (e.g. not served as text/javascript).
