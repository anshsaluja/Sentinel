package dev.sentinel.risk;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * Authenticated, read-only preview endpoints.
 * Caller-supplied grants are for demonstrations ONLY; never treat them as
 * authoritative security findings until sourced from tenant-owned storage.
 */
@RestController
@RequestMapping("/api/v1/risks")
public class RiskApiController {
    private final AccessRiskAnalyzer analyzer = new AccessRiskAnalyzer();
    private final RiskImpactEngine impact = new RiskImpactEngine();

    public record AnalyzeInput(List<AccessRiskAnalyzer.Grant> grants) {}
    public record CompareInput(List<AccessRiskAnalyzer.Grant> before,
                               List<AccessRiskAnalyzer.Grant> after) {}

    @PostMapping("/analyze")
    public List<AccessRiskAnalyzer.Finding> analyze(@AuthenticationPrincipal Jwt jwt,
                                                    @RequestBody AnalyzeInput input) {
        String tenant = tenant(jwt);
        if (input == null || input.grants() == null) throw badRequest();
        requireTenant(tenant, input.grants());
        try {
            return analyzer.analyze(tenant, input.grants());
        } catch (NullPointerException e) {
            throw badRequest();
        }
    }

    @PostMapping("/compare")
    public RiskImpactEngine.Impact compare(@AuthenticationPrincipal Jwt jwt,
                                           @RequestBody CompareInput input) {
        String tenant = tenant(jwt);
        if (input == null || input.before() == null || input.after() == null) throw badRequest();
        requireTenant(tenant, input.before());
        requireTenant(tenant, input.after());
        try {
            return impact.compare(tenant, input.before(), input.after());
        } catch (NullPointerException e) {
            throw badRequest();
        }
    }

    private void requireTenant(String tenant, List<AccessRiskAnalyzer.Grant> grants) {
        if (grants.stream().anyMatch(grant -> grant != null && !tenant.equals(grant.tenantId())))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-tenant grant");
        if (grants.stream().anyMatch(grant -> grant == null)) throw badRequest();
    }

    private String tenant(Jwt jwt) {
        if (jwt == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        String value = jwt.getClaimAsString("tenant_id");
        if (value == null || value.isBlank())
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing tenant claim");
        return value;
    }

    private ResponseStatusException badRequest() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid risk input");
    }
}
