package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Renders comments as raw HTML so the stored XSS payload fires in the
 * browser. DO NOT use this pattern in real applications.
 */
@RestController
@RequestMapping("/comments")
public class CommentViewController {

    private final CommentService commentService;

    public CommentViewController(CommentService commentService) {
        this.commentService = commentService;
    }

    // FIX (CWE-79, OWASP A03:2021 - Stored XSS):
    // Every comment field is HTML-escaped before being concatenated into
    // the response so a malicious body like "<script>alert(1)</script>"
    // can no longer execute when the page is rendered.
    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    public String viewAll() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body><h1>Comments</h1>");
        List<Comment> comments = commentService.findAll();
        for (Comment c : comments) {
            // FIX: escape both author and body so an attacker cannot
            // break out of the surrounding <div> or inject a new <script>.
            sb.append("<div class='comment'>")
              .append("<b>").append(htmlEscape(c.getAuthor())).append(":</b> ")
              .append(htmlEscape(c.getBody()))
              .append("</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    @GetMapping(value = "/{id}", produces = MediaType.TEXT_HTML_VALUE)
    public String viewOne(@PathVariable Long id) {
        Comment c = commentService.findById(id);
        if (c == null) {
            return "<html><body>Not found</body></html>";
        }
        // FIX: HTML-escape the user-supplied author and body before
        // concatenating them into the response.
        return "<html><body><h1>Comment</h1><div><b>"
                + htmlEscape(c.getAuthor()) + ":</b> "
                + htmlEscape(c.getBody()) + "</div></body></html>";
    }

    /**
     * Minimal HTML-attribute / text-content escaper. Replaces the five
     * characters that have special meaning inside HTML text or double-
     * quoted attribute values with their numeric character references.
     */
    private static String htmlEscape(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            switch (ch) {
                case '&'  -> out.append("&amp;");
                case '<'  -> out.append("&lt;");
                case '>'  -> out.append("&gt;");
                case '"'  -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                default   -> out.append(ch);
            }
        }
        return out.toString();
    }
}
