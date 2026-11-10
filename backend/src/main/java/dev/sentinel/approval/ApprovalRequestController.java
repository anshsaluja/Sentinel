package dev.sentinel.approval;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Requesters can submit for review, but cannot grant access to themselves. */
@RestController
@RequestMapping("/api/v1/approval-requests")
public class ApprovalRequestController {
    private final ApprovalRequestService service;

    public ApprovalRequestController(ApprovalRequestService service) {
        this.service = service;
    }

    public record Submission(String resourceId, String justification) {}

    @PostMapping
    @org.springframework.web.bind.annotation.ResponseStatus(HttpStatus.CREATED)
    public ApprovalWorkflow.Request create(@AuthenticationPrincipal Jwt jwt,
                                            @RequestBody Submission submission) {
        if (jwt == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        String tenantId = jwt.getClaimAsString("tenant_id");
        String requesterId = jwt.getSubject();
        if (tenantId == null || tenantId.isBlank() || requesterId == null || requesterId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Verified tenant and subject required");
        }
        if (submission == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Request body required");
        }
        try {
            return service.create(tenantId, requesterId, submission.resourceId(), submission.justification());
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid approval request");
        }
    }
}
