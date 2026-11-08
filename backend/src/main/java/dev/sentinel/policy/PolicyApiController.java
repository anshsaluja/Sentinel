package dev.sentinel.policy;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Objects;

/**
 * Authenticated demonstration API for deterministic policy calculations.
 * Rules are supplied by the caller for preview only: do not use the result
 * as an enforcement decision until rules are loaded from trusted persistence.
 */
@RestController
@RequestMapping("/api/v1/policies")
public class PolicyApiController {
    private final PolicyDecisionEngine decisions = new PolicyDecisionEngine();
    private final PolicySimulationEngine simulation = new PolicySimulationEngine();

    public record EvaluateInput(PolicyDecisionEngine.Request request,
                                List<PolicyDecisionEngine.Rule> rules) {}
    public record SimulateInput(List<PolicySimulationEngine.Subject> subjects,
                                List<PolicyDecisionEngine.Rule> before,
                                List<PolicyDecisionEngine.Rule> after) {}

    @PostMapping("/evaluate")
    public PolicyDecisionEngine.Decision evaluate(@AuthenticationPrincipal Jwt jwt,
                                                  @RequestBody EvaluateInput input) {
        String tenant = authenticatedTenant(jwt);
        if (input == null || input.request() == null || input.rules() == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing evaluation fields");
        if (!tenant.equals(input.request().tenantId()) ||
                input.rules().stream().anyMatch(rule -> rule == null || !tenant.equals(rule.tenantId())))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-tenant input");
        return decisions.evaluate(input.request(), input.rules());
    }

    @PostMapping("/simulate")
    public PolicySimulationEngine.Preview simulate(@AuthenticationPrincipal Jwt jwt,
                                                    @RequestBody SimulateInput input) {
        String tenant = authenticatedTenant(jwt);
        if (input == null || input.subjects() == null || input.before() == null || input.after() == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing simulation fields");
        try {
            return simulation.preview(tenant, input.subjects(), input.before(), input.after());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-tenant input");
        } catch (NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Null simulation entry");
        }
    }

    private String authenticatedTenant(Jwt jwt) {
        if (jwt == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        String tenant = jwt.getClaimAsString("tenant_id");
        if (tenant == null || tenant.isBlank())
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing tenant claim");
        return tenant;
    }
}
