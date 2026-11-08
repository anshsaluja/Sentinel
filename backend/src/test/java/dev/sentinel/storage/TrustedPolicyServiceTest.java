package dev.sentinel.storage;

import dev.sentinel.policy.PolicyDecisionEngine;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustedPolicyServiceTest {
    private final PolicyRepository repository = mock(PolicyRepository.class);
    private final TrustedPolicyService service = new TrustedPolicyService(repository);

    private PolicyDecisionEngine.Request request() {
        return new PolicyDecisionEngine.Request("alpha", "ledger", "read",
                Set.of("analyst"), Map.of("department", "finance"));
    }

    private StoredPolicy policy(String tenant, boolean enabled, PolicyDecisionEngine.Effect effect) {
        return new StoredPolicy(null, tenant, "policy-1", "ledger", "read",
                Set.of("analyst"), Map.of("department", "finance"), effect, enabled);
    }

    @Test void trustedAllowIsApplied() {
        when(repository.findByTenantIdAndResourceIdAndActionAndEnabledTrue("alpha", "ledger", "read"))
                .thenReturn(List.of(policy("alpha", true, PolicyDecisionEngine.Effect.ALLOW)));
        assertTrue(service.evaluate(request()).allowed());
        verify(repository).findByTenantIdAndResourceIdAndActionAndEnabledTrue("alpha", "ledger", "read");
    }

    @Test void missingPolicyDeniesByDefault() {
        when(repository.findByTenantIdAndResourceIdAndActionAndEnabledTrue("alpha", "ledger", "read"))
                .thenReturn(List.of());
        assertEquals("default_deny", service.evaluate(request()).reason());
    }

    @Test void foreignTenantRowCannotGrantAccess() {
        when(repository.findByTenantIdAndResourceIdAndActionAndEnabledTrue("alpha", "ledger", "read"))
                .thenReturn(List.of(policy("beta", true, PolicyDecisionEngine.Effect.ALLOW)));
        assertEquals("tenant_scope_violation", service.evaluate(request()).reason());
    }

    @Test void listRejectsForeignTenantRow() {
        when(repository.findByTenantIdAndEnabledTrue("alpha"))
                .thenReturn(List.of(policy("beta", true, PolicyDecisionEngine.Effect.ALLOW)));
        assertThrows(IllegalStateException.class, () -> service.listEnabled("alpha"));
    }

    @Test void explicitDenyOverridesTrustedAllow() {
        when(repository.findByTenantIdAndResourceIdAndActionAndEnabledTrue("alpha", "ledger", "read"))
                .thenReturn(List.of(policy("alpha", true, PolicyDecisionEngine.Effect.ALLOW),
                        policy("alpha", true, PolicyDecisionEngine.Effect.DENY)));
        assertEquals("explicit_deny", service.evaluate(request()).reason());
    }
}
