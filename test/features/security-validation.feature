@security-validation
Feature: Security validation from manual test contract
  Background:
    Given the OWASP lab application is reachable on http://localhost:8080

  Scenario: Verify that the /api/deserialize endpoint rejects gadget-chain deserialisation payloads (ObjectInputFilter whitelisting)
    Given the manual test case "TC-VULN-001-001" is available
    Then the automation harness validates the scenario

  Scenario: Verify that /api/comment/greet HTML-escapes the 'name' query parameter to prevent reflected XSS
    Given the manual test case "TC-VULN-001-002" is available
    Then the automation harness validates the scenario
