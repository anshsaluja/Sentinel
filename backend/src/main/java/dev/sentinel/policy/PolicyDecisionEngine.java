package dev.sentinel.policy;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Deterministic deny-by-default RBAC/ABAC evaluation.
 * Domain-level isolation is defense in depth; API security must independently
 * derive the tenant from an authenticated identity, not user input.
 */
public final class PolicyDecisionEngine {
    public enum Effect { ALLOW, DENY }

    public record Rule(String tenantId, String resourceId, String action,
                       Set<String> roles, Map<String, String> attributes, Effect effect) {
        public Rule {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(resourceId);
            Objects.requireNonNull(action);
            roles = Set.copyOf(Objects.requireNonNull(roles));
            attributes = Map.copyOf(Objects.requireNonNull(attributes));
            Objects.requireNonNull(effect);
        }
    }

    public record Request(String tenantId, String resourceId, String action,
                          Set<String> roles, Map<String, String> attributes) {
        public Request {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(resourceId);
            Objects.requireNonNull(action);
            roles = Set.copyOf(Objects.requireNonNull(roles));
            attributes = Map.copyOf(Objects.requireNonNull(attributes));
        }
    }

    public record Decision(boolean allowed, String reason) {}

    public Decision evaluate(Request request, List<Rule> rules) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(rules);
        boolean matchedAllow = false;
        for (Rule rule : rules) {
            if (!rule.tenantId().equals(request.tenantId())
                    || !rule.resourceId().equals(request.resourceId())
                    || !rule.action().equals(request.action())) continue;
            if (rule.roles().isEmpty() || request.roles().stream().noneMatch(rule.roles()::contains)) continue;
            if (!request.attributes().entrySet().containsAll(rule.attributes().entrySet())) continue;
            if (rule.effect() == Effect.DENY) return new Decision(false, "explicit_deny");
            matchedAllow = true;
        }
        return matchedAllow ? new Decision(true, "matching_allow")
                : new Decision(false, "default_deny");
    }
}
