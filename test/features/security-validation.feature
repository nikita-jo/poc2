@security-validation
@OWASP-VULN-001
Feature: Security validation of the OWASP VULN-001 remediation
  The /api/deserialize endpoint MUST NOT execute gadget-chain Java
  deserialisation payloads (CWE-502) and the /api/comment/greet endpoint
  MUST HTML-escape the reflected `name` query parameter to prevent
  reflected XSS (CWE-79).

  These scenarios are the source-of-truth automation for the
  manual test contract in manualtestJSON/vulntestcase.json
  (TC-VULN-001-001 and TC-VULN-001-002).

  Background:
    Given the OWASP lab application is reachable on http://localhost:8080
    And a registered test user is authenticated via HTTP Basic

  # -----------------------------------------------------------------
  # TC-VULN-001-001 — Deserialization gadget-chain rejection
  # -----------------------------------------------------------------
  @TC-VULN-001-001 @CWE-502 @severity-critical
  Scenario: POST /api/deserialize accepts a benign whitelisted payload
    Given a Base64-encoded Java serialised HashMap
    And the client POSTs the benign payload to /api/deserialize
    Then the response status is 200
    And the response body identifies a parsed Map type

  @TC-VULN-001-001 @CWE-502 @severity-critical
  Scenario: POST /api/deserialize rejects an Apache Commons Collections gadget payload
    Given a Base64-encoded Java serialised InvokerTransformer gadget payload
    And the client POSTs the InvokerTransformer gadget payload to /api/deserialize
    Then the response status is NOT 200
    And the response body does not contain "Map<String,Object>"

  @TC-VULN-001-001 @CWE-502 @severity-critical
  Scenario: POST /api/deserialize rejects a Spring framework gadget payload
    Given a Base64-encoded Java serialised Spring ObjectFactory gadget payload
    And the client POSTs the Spring ObjectFactory gadget payload to /api/deserialize
    Then the response status is NOT 200
    And the response body does not contain "Map<String,Object>"

  @TC-VULN-001-001 @CWE-502 @severity-critical
  Scenario: POST /api/deserialize rejects a Groovy gadget payload
    Given a Base64-encoded Java serialised GroovyObject gadget payload
    And the client POSTs the GroovyObject gadget payload to /api/deserialize
    Then the response status is NOT 200
    And the response body does not contain "Map<String,Object>"

  # -----------------------------------------------------------------
  # TC-VULN-001-002 — Reflected XSS escaping
  # -----------------------------------------------------------------
  @TC-VULN-001-002 @CWE-79 @severity-high
  Scenario: GET /api/comment/greet returns the baseline greeting for a safe name
    Given the user issues GET /api/comment/greet?name=Alice
    Then the response status is 200
    And the response Content-Type is text/html
    And the response body contains "Hello, Alice!"

  @TC-VULN-001-002 @CWE-79 @severity-high
  Scenario: GET /api/comment/greet HTML-escapes a <script> XSS payload
    Given the user issues GET /api/comment/greet with name "<script>alert('XSS')</script>"
    Then the response status is 200
    And the response body contains the entity-encoded "<script>alert('XSS')</script>" token
    And the response body does not contain the raw "<script>" substring

  @TC-VULN-001-002 @CWE-79 @severity-high
  Scenario: GET /api/comment/greet HTML-escapes an <img onerror> XSS payload
    Given the user issues GET /api/comment/greet with name "<img src=x onerror=alert(1)>"
    Then the response status is 200
    And the response body contains the entity-encoded "<img src=x onerror=alert(1)>" token
    And the response body does not contain the raw "<img" substring

  @TC-VULN-001-002 @CWE-79 @severity-high
  Scenario: GET /api/comment/greet HTML-escapes a "><svg/onload> XSS payload
    Given the user issues GET /api/comment/greet with name "\"><svg/onload=alert(1)>"
    Then the response status is 200
    And the response body contains the entity-encoded "\"><svg/onload=alert(1)>" token
    And the response body does not contain the raw "\">" substring

  @TC-VULN-001-002 @CWE-79 @severity-high
  Scenario: GET /api/comment/greet defaults to "World" when the name parameter is missing
    Given the user issues GET /api/comment/greet with no name parameter
    Then the response status is 200
    And the response body contains "Hello, World!"
