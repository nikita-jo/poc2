@security-validation
Feature: Security validation from manual test contract

  The scenarios in this file are generated from
  `manualtestJSON/vulntestcase.json`. Each scenario exercises one manual
  security test case against the running OWASP lab application on
  `http://localhost:8080`.

  Background:
    Given the OWASP lab application is reachable on http://localhost:8080

  # Agent contract: You are an elite QA Automation Engineer -- an autonomous agent specialized in transforming manual test specifications into production-grade end-to-end automation suites. You are an expert in Playwrigh

  @security @severity-CRITICAL @CWE_502 @id-TC_VULN_001_007
  Scenario: [TC-VULN-001-007] Deserialization (POST /api/deserialize)
    Given Send a POST request to /api/deserialize with a well-formed json body to confirm the endpoint responds successfully.
    Then Send a POST request to /api/deserialize with a well-formed json body and confirm the server responds with HTTP 200.
    Then Send a POST request to /api/deserialize with Content-Type: application/octet-stream and a gadget payload and confirm the server responds with HTTP 415.
    Then Send a POST request to /api/deserialize with a malformed json body and confirm the server responds with HTTP 400.

  @security @severity-HIGH @CWE_79 @id-TC_VULN_001_008
  Scenario: [TC-VULN-001-008] Reflected XSS (GET /api/comment/greet)
    Given Send GET /api/comment/greet?name=baseline to confirm the endpoint responds successfully.
    Then Send GET /api/comment/greet?name=<script>alert('XSS')</script> to verify HTML-escaping in the reflected-XSS response.
    Then Confirm the response does not appear to contain the raw <script> tag in the reflected-XSS response.

  @security @severity-HIGH @CWE_79 @id-TC_VULN_001_009
  Scenario: [TC-VULN-001-009] Stored XSS (GET /comments)
    Given Send GET /comments?name=baseline to confirm the endpoint responds successfully.
    Then Send GET /comments?name=<script>alert('XSS')</script> to verify HTML-escaping in the stored-XSS response.
    Then Confirm the response does not appear to contain the raw <script> tag in the stored-XSS response.

  @security @severity-CRITICAL @CWE_89 @id-TC_VULN_001_010
  Scenario: [TC-VULN-001-010] SQLi (GET /users)
    Given Send GET /users?name=baseline to confirm the endpoint responds successfully.
    Then Send GET /users?name=' OR '1'='1 to verify the parameterized query rejects SQL injection.
    Then Verify the server logs do not contain evidence of SQL injection.
