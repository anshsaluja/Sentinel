package dev.sentinel.policy;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class PolicyDecisionEngineTest {
    private final PolicyDecisionEngine engine = new PolicyDecisionEngine();

    private PolicyDecisionEngine.Rule rule(String tenant, PolicyDecisionEngine.Effect effect) {
        return new PolicyDecisionEngine.Rule(tenant, "payments", "read", Set.of("analyst"),
                Map.of("department", "finance"), effect);
    }

    private PolicyDecisionEngine.Request request(String tenant, Map<String,String> attributes) {
        return new PolicyDecisionEngine.Request(tenant, "payments", "read",
                Set.of("analyst"), attributes);
    }

    @Test void matchingGrantAllows() {
        assertTrue(engine.evaluate(request("alpha", Map.of("department", "finance")),
                List.of(rule("alpha", PolicyDecisionEngine.Effect.ALLOW))).allowed());
    }
    @Test void crossTenantGrantIsIgnored() {
        assertFalse(engine.evaluate(request("beta", Map.of("department", "finance")),
                List.of(rule("alpha", PolicyDecisionEngine.Effect.ALLOW))).allowed());
    }
    @Test void mismatchingAbacConstraintDenies() {
        assertFalse(engine.evaluate(request("alpha", Map.of("department", "sales")),
                List.of(rule("alpha", PolicyDecisionEngine.Effect.ALLOW))).allowed());
    }
    @Test void explicitDenyOverridesAllowRegardlessOfOrdering() {
        var input = request("alpha", Map.of("department", "finance"));
        var allow = rule("alpha", PolicyDecisionEngine.Effect.ALLOW);
        var deny = rule("alpha", PolicyDecisionEngine.Effect.DENY);
        assertEquals("explicit_deny", engine.evaluate(input, List.of(allow, deny)).reason());
        assertEquals("explicit_deny", engine.evaluate(input, List.of(deny, allow)).reason());
    }
    @Test void noRulesDeniesByDefault() {
        assertEquals("default_deny", engine.evaluate(request("alpha", Map.of()), List.of()).reason());
    }
}
