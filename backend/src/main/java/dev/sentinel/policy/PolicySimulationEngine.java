package dev.sentinel.policy;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Side-effect-free impact preview. Never mutates grants or policy state.
 * Input subjects must be loaded from an authenticated tenant's data scope.
 */
public final class PolicySimulationEngine {
    private final PolicyDecisionEngine decisions = new PolicyDecisionEngine();

    public record Subject(String userId, PolicyDecisionEngine.Request request) {
        public Subject { Objects.requireNonNull(userId); Objects.requireNonNull(request); }
    }
    public record Change(String userId, String resourceId, String action,
                         boolean beforeAllowed, boolean afterAllowed) {}
    public record Preview(int gained, int lost, int unchanged, List<Change> changes) {
        public Preview { changes = List.copyOf(changes); }
    }

    public Preview preview(String tenantId, List<Subject> subjects,
                           List<PolicyDecisionEngine.Rule> before,
                           List<PolicyDecisionEngine.Rule> after) {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(subjects);
        Objects.requireNonNull(before);
        Objects.requireNonNull(after);
        if (before.stream().anyMatch(rule -> !tenantId.equals(rule.tenantId()))
                || after.stream().anyMatch(rule -> !tenantId.equals(rule.tenantId()))) {
            throw new IllegalArgumentException("Policy rules cannot cross tenant boundaries");
        }
        var changes = new ArrayList<Change>();
        int gained = 0, lost = 0, unchanged = 0;
        for (Subject subject : subjects) {
            var request = subject.request();
            if (!tenantId.equals(request.tenantId())) {
                throw new IllegalArgumentException("Subjects cannot cross tenant boundaries");
            }
            boolean oldAccess = decisions.evaluate(request, before).allowed();
            boolean newAccess = decisions.evaluate(request, after).allowed();
            if (!oldAccess && newAccess) gained++;
            else if (oldAccess && !newAccess) lost++;
            else unchanged++;
            if (oldAccess != newAccess) {
                changes.add(new Change(subject.userId(), request.resourceId(),
                        request.action(), oldAccess, newAccess));
            }
        }
        changes.sort(Comparator.comparing(Change::userId)
                .thenComparing(Change::resourceId).thenComparing(Change::action));
        return new Preview(gained, lost, unchanged, changes);
    }
}
