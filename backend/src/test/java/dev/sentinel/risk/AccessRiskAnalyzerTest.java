package dev.sentinel.risk;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AccessRiskAnalyzerTest {
    private final AccessRiskAnalyzer analyzer = new AccessRiskAnalyzer();
    private AccessRiskAnalyzer.Grant grant(String tenant, String user, String permission, boolean active) {
        return new AccessRiskAnalyzer.Grant(tenant, user, "billing", permission, active);
    }
    @Test void flagsWildcardAndOrphanedAccess() {
        var findings = analyzer.analyze("acme", List.of(grant("acme", "alice", "*", false)));
        assertEquals(2, findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.code().equals("BROAD_PRIVILEGE")));
        assertTrue(findings.stream().anyMatch(f -> f.code().equals("ORPHANED_ACCESS")));
    }
    @Test void flagsPaymentSegregationOfDutiesConflict() {
        var findings = analyzer.analyze("acme", List.of(
                grant("acme", "alice", "payment:approve", true),
                grant("acme", "alice", "payment:execute", true)));
        assertEquals(1, findings.size());
        assertEquals("SEGREGATION_OF_DUTIES", findings.getFirst().code());
    }
    @Test void noFalsePositiveAcrossDifferentUsers() {
        assertTrue(analyzer.analyze("acme", List.of(
                grant("acme", "alice", "payment:approve", true),
                grant("acme", "bob", "payment:execute", true))).isEmpty());
    }
    @Test void rejectsForeignTenantGrants() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.analyze("acme",
                List.of(grant("other", "alice", "*", true))));
    }
    @Test void duplicateGrantsDoNotMultiplyFindings() {
        var grant = grant("acme", "alice", "*", true);
        assertEquals(1, analyzer.analyze("acme", List.of(grant, grant)).size());
    }
}
