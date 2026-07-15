package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Comment endpoints - used to demonstrate XSS.
 */
@RestController
@RequestMapping("/api/comment")
public class CommentController {

    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - Injection / XSS - Stored):
    // Comment body is stored raw and later echoed back inside HTML
    // WITHOUT escaping. POST a comment containing:
    //   <script>alert('XSS')</script>
    // and the script will fire when the HTML page is rendered.
    // ----------------------------------------------------------------
    @PostMapping
    public Comment create(@RequestBody Comment c) {
        return commentService.save(c);
    }

    @GetMapping
    public List<Comment> all() {
        return commentService.findAll();
    }

    // ----------------------------------------------------------------
    // FIX (CWE-79, OWASP A03:2021 - Reflected XSS):
    // The "name" query parameter is HTML-escaped before being
    // interpolated into the response so a payload like
    //   /api/comment/greet?name=<script>alert('XSS')</script>
    // no longer executes in the browser.
    // ----------------------------------------------------------------
    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
        // FIX: HTML-escape user-controlled input before interpolating it
        // into the response body. This neutralises <script>, <img onerror=...>,
        // and similar payloads without changing the legitimate "Hello, <name>!"
        // behaviour for non-malicious callers.
        String safe = name == null ? "World" : htmlEscape(name);
        return "<html><body><h1>Hello, " + safe + "!</h1></body></html>";
    }

    /**
     * Minimal HTML-attribute / text-content escaper. Replaces the five
     * characters that have special meaning inside HTML text or double-
     * quoted attribute values with their numeric character references.
     * <p>
     * This is intentionally a small, dependency-free implementation so the
     * lab project keeps its existing pom.xml. A production codebase should
     * use the OWASP Java Encoder project instead.
     */
    private static String htmlEscape(String input) {
        StringBuilder out = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&'  -> out.append("&amp;");
                case '<'  -> out.append("&lt;");
                case '>'  -> out.append("&gt;");
                case '"'  -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                default   -> out.append(c);
            }
        }
        return out.toString();
    }
}
