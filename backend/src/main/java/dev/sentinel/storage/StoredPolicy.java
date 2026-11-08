package dev.sentinel.storage;

import dev.sentinel.policy.PolicyDecisionEngine;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Persisted tenant-owned policy. Caller-provided policy IDs are never used to
 * query without an authenticated tenant scope.
 */
@Document(collection = "policies")
@CompoundIndex(name = "tenant_policy_unique", def = "{'tenantId': 1, 'policyId': 1}", unique = true)
public record StoredPolicy(
        @Id String id,
        String tenantId,
        String policyId,
        String resourceId,
        String action,
        Set<String> roles,
        Map<String, String> attributes,
        PolicyDecisionEngine.Effect effect,
        boolean enabled
) {
    public StoredPolicy {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(policyId);
        Objects.requireNonNull(resourceId);
        Objects.requireNonNull(action);
        roles = Set.copyOf(Objects.requireNonNull(roles));
        attributes = Map.copyOf(Objects.requireNonNull(attributes));
        Objects.requireNonNull(effect);
    }

    public PolicyDecisionEngine.Rule asRule() {
        return new PolicyDecisionEngine.Rule(tenantId, resourceId, action, roles, attributes, effect);
    }
}
