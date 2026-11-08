package dev.sentinel.risk;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Explainable, deterministic risk signals over tenant-scoped grants.
 * This is a focused rules engine, not a claim of complete compliance coverage.
 */
public final class AccessRiskAnalyzer {
    public record Grant(String tenantId, String userId, String resourceId,
                        String permission, boolean activeUser) {
        public Grant {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(userId);
            Objects.requireNonNull(resourceId);
            Objects.requireNonNull(permission);
        }
    }
    public enum Severity { HIGH, MEDIUM }
    public record Finding(String tenantId, String userId, String resourceId,
                          String code, Severity severity, String explanation) {}

    public List<Finding> analyze(String tenantId, List<Grant> grants) {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(grants);
        if (grants.stream().anyMatch(g -> !tenantId.equals(g.tenantId()))) {
            throw new IllegalArgumentException("Grants cannot cross tenant boundaries");
        }
        var findings = new ArrayList<Finding>();
        var seen = new HashSet<String>();
        for (Grant grant : grants) {
            String key = grant.userId() + "\u0000" + grant.resourceId() + "\u0000" + grant.permission();
            if (!seen.add(key)) continue;
            if (!grant.activeUser()) {
                findings.add(new Finding(tenantId, grant.userId(), grant.resourceId(),
                        "ORPHANED_ACCESS", Severity.HIGH, "Inactive user retains access"));
            }
            if ("*".equals(grant.permission()) || "admin:*".equals(grant.permission())) {
                findings.add(new Finding(tenantId, grant.userId(), grant.resourceId(),
                        "BROAD_PRIVILEGE", Severity.HIGH, "Wildcard privilege grants excessive access"));
            }
        }
        Set<String> approvers = new HashSet<>();
        Set<String> payers = new HashSet<>();
        for (Grant grant : grants) {
            String key = grant.userId() + "\u0000" + grant.resourceId();
            if ("payment:approve".equals(grant.permission())) approvers.add(key);
            if ("payment:execute".equals(grant.permission())) payers.add(key);
        }
        approvers.retainAll(payers);
        for (String key : approvers) {
            int split = key.indexOf('\u0000');
            findings.add(new Finding(tenantId, key.substring(0, split), key.substring(split + 1),
                    "SEGREGATION_OF_DUTIES", Severity.HIGH,
                    "Same user can approve and execute payments"));
        }
        findings.sort(Comparator.comparing(Finding::userId).thenComparing(Finding::resourceId)
                .thenComparing(Finding::code));
        return List.copyOf(findings);
    }
}
