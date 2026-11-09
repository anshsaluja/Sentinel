package dev.sentinel.approval;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Tenant-scoped, read-only approval queue for the authenticated dashboard.
 * Transitions are deliberately not exposed until reviewer authorization and
 * transactional audit integration are tested end-to-end.
 */
@RestController
@RequestMapping("/api/v1/approvals")
public class ApprovalApiController {
    private final ApprovalPersistenceService approvals;

    public ApprovalApiController(ApprovalPersistenceService approvals) {
        this.approvals = approvals;
    }

    @GetMapping("/pending")
    public List<ApprovalWorkflow.Request> pending(@AuthenticationPrincipal Jwt jwt) {
        String tenantId = tenant(jwt);
        requireReviewer(jwt);
        return approvals.pending(tenantId);
    }

    @GetMapping("/{requestId}")
    public ApprovalWorkflow.Request find(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable String requestId) {
        String tenantId = tenant(jwt);
        requireReviewer(jwt);
        if (requestId == null || !requestId.matches("[a-zA-Z0-9_.:-]{1,120}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid approval identifier");
        }
        try {
            return approvals.find(tenantId, requestId);
        } catch (IllegalArgumentException notFound) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Approval not found");
        }
    }

    private static void requireReviewer(Jwt jwt) {
        Object access = jwt.getClaim("realm_access");
        Object roles = access instanceof Map<?, ?> realm ? realm.get("roles") : null;
        if (!(roles instanceof List<?> roleList) ||
                (!roleList.contains("sentinel-reviewer") && !roleList.contains("sentinel-admin"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Reviewer role required");
        }
    }

    private static String tenant(Jwt jwt) {
        if (jwt == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        String tenantId = jwt.getClaimAsString("tenant_id");
        if (tenantId == null || tenantId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing tenant claim");
        }
        return tenantId;
    }
}
