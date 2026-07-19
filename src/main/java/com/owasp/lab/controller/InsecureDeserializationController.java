package com.owasp.lab.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Secure replacement for the legacy deserialisation endpoint.
 *
 * REMEDIATION (OWASP A08:2021 - Software and Data Integrity Failures):
 *  - Native Java deserialisation (ObjectInputStream) is REMOVED entirely.
 *    It is replaced with a strict JSON parse using Jackson, which is
 *    not vulnerable to gadget-chain RCE because only declared POJO fields
 *    are populated.
 *  - fail-on-unknown-properties is enforced in the global Jackson
 *    configuration (see application.properties) so undeclared fields
 *    are rejected.
 *  - The endpoint accepts an arbitrary JSON object and echoes back the
 *    parsed type name so the lab's API shape is preserved.
 *  - Malformed JSON or an unparseable body is mapped to HTTP 400
 *    (Bad Request) via the local @ExceptionHandler below, instead of
 *    leaking the parser stack trace as an HTTP 500.
 */
@RestController
@RequestMapping("/api/deserialize")
public class InsecureDeserializationController {

    private final ObjectMapper objectMapper;

    public InsecureDeserializationController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
        // SAFE: parse as untyped JSON (Map). Never call readObject().
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(body, Map.class);
        return ResponseEntity.ok(Map.of(
                "type", "Map<String,Object>",
                "size", parsed == null ? 0 : parsed.size()
        ));
    }

    /**
     * Map any JSON parse failure to a clean 400 so callers see a
     * proper Bad Request response instead of a 500 with a Jackson
     * stack trace.  The response body is intentionally minimal and
     * does not echo the offending payload (avoids reflected-XSS
     * surface in this JSON endpoint).
     */
    @ExceptionHandler({ JsonProcessingException.class, HttpMessageNotReadableException.class })
    public ResponseEntity<Map<String, Object>> handleUnparseableBody(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "type", "Map<String,Object>",
                "size", 0,
                "error", "malformed JSON body"
        ));
    }
}
