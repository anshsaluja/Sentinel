package dev.sentinel.risk;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Side-effect-free risk delta between current and proposed tenant grants. */
public final class RiskImpactEngine {
    public enum ChangeType { INTRODUCED, RESOLVED }
    public record Change(ChangeType type, AccessRiskAnalyzer.Finding finding) {}
    public record Impact(int introduced, int resolved, int remaining, List<Change> changes) {
        public Impact { changes = List.copyOf(changes); }
    }

    private final AccessRiskAnalyzer analyzer = new AccessRiskAnalyzer();

    public Impact compare(String tenantId, List<AccessRiskAnalyzer.Grant> current,
                          List<AccessRiskAnalyzer.Grant> proposed) {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(current);
        Objects.requireNonNull(proposed);
        // Analyzer checks tenant boundaries before computing findings.
        var before = index(analyzer.analyze(tenantId, current));
        var after = index(analyzer.analyze(tenantId, proposed));
        var changes = new ArrayList<Change>();
        for (var entry : after.entrySet()) {
            if (!before.containsKey(entry.getKey()))
                changes.add(new Change(ChangeType.INTRODUCED, entry.getValue()));
        }
        for (var entry : before.entrySet()) {
            if (!after.containsKey(entry.getKey()))
                changes.add(new Change(ChangeType.RESOLVED, entry.getValue()));
        }
        changes.sort(Comparator.comparing((Change c) -> c.finding().userId())
                .thenComparing(c -> c.finding().resourceId())
                .thenComparing(c -> c.finding().code())
                .thenComparing(c -> c.type().name()));
        int introduced = (int) changes.stream().filter(c -> c.type() == ChangeType.INTRODUCED).count();
        return new Impact(introduced, changes.size() - introduced,
                after.size() - introduced, changes);
    }

    private Map<String, AccessRiskAnalyzer.Finding> index(List<AccessRiskAnalyzer.Finding> findings) {
        var indexed = new HashMap<String, AccessRiskAnalyzer.Finding>();
        for (var finding : findings) {
            // Length-prefixed components avoid delimiter collisions.
            var key = part(finding.tenantId()) + part(finding.userId())
                    + part(finding.resourceId()) + part(finding.code());
            indexed.put(key, finding);
        }
        return indexed;
    }

    private String part(String value) { return value.length() + ":" + value; }
}
