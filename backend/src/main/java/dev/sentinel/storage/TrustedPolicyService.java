package dev.sentinel.storage;

import dev.sentinel.policy.PolicyDecisionEngine;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

/**
 * Loads authorization policies from trusted storage instead of accepting
 * caller-supplied rules. Tenant MUST come from a verified JWT claim.
 */
@Service
public final class TrustedPolicyService {
    private final PolicyRepository repository;
    private final PolicyDecisionEngine engine = new PolicyDecisionEngine();

    public TrustedPolicyService(PolicyRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    public PolicyDecisionEngine.Decision evaluate(PolicyDecisionEngine.Request request) {
        Objects.requireNonNull(request);
        var policies = repository.findByTenantIdAndResourceIdAndActionAndEnabledTrue(
                request.tenantId(), request.resourceId(), request.action());
        if (policies.stream().anyMatch(policy -> !request.tenantId().equals(policy.tenantId()))) {
            // Defense in depth: a faulty repository or index must not grant cross-tenant access.
            return new PolicyDecisionEngine.Decision(false, "tenant_scope_violation");
        }
        List<PolicyDecisionEngine.Rule> rules = policies.stream()
                .map(StoredPolicy::asRule)
                .toList();
        return engine.evaluate(request, rules);
    }

    public List<StoredPolicy> listEnabled(String tenantId) {
        Objects.requireNonNull(tenantId);
        var policies = repository.findByTenantIdAndEnabledTrue(tenantId);
        if (policies.stream().anyMatch(policy -> !tenantId.equals(policy.tenantId()))) {
            throw new IllegalStateException("Tenant-scoped policy repository returned foreign data");
        }
        return List.copyOf(policies);
    }
}
