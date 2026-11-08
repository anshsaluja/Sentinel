package dev.sentinel.risk;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RiskImpactEngineTest {
    private final RiskImpactEngine engine = new RiskImpactEngine();

    private AccessRiskAnalyzer.Grant grant(String user, String permission) {
        return new AccessRiskAnalyzer.Grant("acme", user, "payments", permission, true);
    }

    @Test void introducingSegregationConflictIsReported() {
        var before = List.of(grant("alice", "payment:approve"));
        var after = List.of(grant("alice", "payment:approve"), grant("alice", "payment:execute"));
        var impact = engine.compare("acme", before, after);
        assertEquals(1, impact.introduced());
        assertEquals(0, impact.resolved());
        assertEquals(0, impact.remaining());
        assertEquals("SEGREGATION_OF_DUTIES", impact.changes().getFirst().finding().code());
        assertEquals(RiskImpactEngine.ChangeType.INTRODUCED, impact.changes().getFirst().type());
    }

    @Test void removingConflictIsReportedAsResolved() {
        var before = List.of(grant("alice", "payment:approve"), grant("alice", "payment:execute"));
        var after = List.of(grant("alice", "payment:approve"));
        var impact = engine.compare("acme", before, after);
        assertEquals(0, impact.introduced());
        assertEquals(1, impact.resolved());
        assertEquals(0, impact.remaining());
    }

    @Test void unchangedRisksRemainWithoutSpuriousChanges() {
        var grants = List.of(grant("alice", "*"));
        var impact = engine.compare("acme", grants, grants);
        assertEquals(0, impact.introduced());
        assertEquals(0, impact.resolved());
        assertEquals(1, impact.remaining());
        assertTrue(impact.changes().isEmpty());
    }

    @Test void rejectsForeignTenantBeforeOrAfter() {
        var foreign = List.of(new AccessRiskAnalyzer.Grant("other", "bob", "payments", "*", true));
        assertThrows(IllegalArgumentException.class,
                () -> engine.compare("acme", foreign, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> engine.compare("acme", List.of(), foreign));
    }

    @Test void deterministicSortedFindingsAndImmutableOutput() {
        var proposed = List.of(grant("zoe", "*"), grant("amy", "*"));
        var impact = engine.compare("acme", List.of(), proposed);
        assertEquals(List.of("amy", "zoe"),
                impact.changes().stream().map(c -> c.finding().userId()).toList());
        assertThrows(UnsupportedOperationException.class,
                () -> impact.changes().clear());
    }
}
