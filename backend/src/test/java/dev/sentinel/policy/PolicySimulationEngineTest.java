package dev.sentinel.policy;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class PolicySimulationEngineTest {
    private final PolicySimulationEngine engine = new PolicySimulationEngine();

    private PolicyDecisionEngine.Rule grant(String tenant, String role) {
        return new PolicyDecisionEngine.Rule(tenant, "ledger", "read", Set.of(role),
                Map.of(), PolicyDecisionEngine.Effect.ALLOW);
    }

    private PolicySimulationEngine.Subject subject(String user, String tenant, String role) {
        return new PolicySimulationEngine.Subject(user,
                new PolicyDecisionEngine.Request(tenant, "ledger", "read", Set.of(role), Map.of()));
    }

    @Test void previewsGainsAndLossesWithoutChangingInputs() {
        var subjects = List.of(subject("alice", "acme", "analyst"), subject("bob", "acme", "manager"));
        var before = List.of(grant("acme", "analyst"));
        var after = List.of(grant("acme", "manager"));
        var preview = engine.preview("acme", subjects, before, after);
        assertEquals(1, preview.gained());
        assertEquals(1, preview.lost());
        assertEquals(0, preview.unchanged());
        assertEquals("alice", preview.changes().get(0).userId());
        assertEquals("bob", preview.changes().get(1).userId());
        assertEquals(1, before.size());
        assertEquals(1, after.size());
    }

    @Test void rejectsCrossTenantSubjects() {
        assertThrows(IllegalArgumentException.class, () -> engine.preview("acme",
                List.of(subject("intruder", "other", "analyst")),
                List.of(), List.of()));
    }

    @Test void rejectsCrossTenantPolicyRules() {
        assertThrows(IllegalArgumentException.class, () -> engine.preview("acme",
                List.of(subject("alice", "acme", "analyst")),
                List.of(), List.of(grant("other", "analyst"))));
    }

    @Test void reportsUnchangedDecisionsWithoutSpuriousChanges() {
        var preview = engine.preview("acme", List.of(subject("alice", "acme", "analyst")),
                List.of(grant("acme", "analyst")), List.of(grant("acme", "analyst")));
        assertEquals(1, preview.unchanged());
        assertTrue(preview.changes().isEmpty());
    }
}
