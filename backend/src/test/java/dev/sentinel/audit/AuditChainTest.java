package dev.sentinel.audit;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AuditChainTest {
    private final AuditChain chain = new AuditChain();
    private final Instant now = Instant.parse("2026-11-08T05:00:00Z");

    private AuditChain.Event first() {
        return chain.append("alpha", "alice", "REQUEST", "r1", now, List.of());
    }

    @Test void validSequenceVerifies() {
        var a = first();
        var b = chain.append("alpha", "bob", "APPROVE", "r1", now.plusSeconds(1), List.of(a));
        assertTrue(chain.verify("alpha", List.of(a, b)));
        assertEquals(2, b.sequence());
        assertEquals(a.hash(), b.previousHash());
    }

    @Test void crossTenantChainFails() {
        assertFalse(chain.verify("beta", List.of(first())));
    }

    @Test void modifiedEventFails() {
        var a = first();
        var altered = new AuditChain.Event(a.tenantId(), a.sequence(), a.occurredAt(),
                a.actorId(), "REJECT", a.targetId(), a.previousHash(), a.hash());
        assertFalse(chain.verify("alpha", List.of(altered)));
    }

    @Test void reorderedEventsFail() {
        var a = first();
        var b = chain.append("alpha", "bob", "APPROVE", "r1", now.plusSeconds(1), List.of(a));
        assertFalse(chain.verify("alpha", List.of(b, a)));
    }

    @Test void duplicateSequenceFails() {
        var a = first();
        assertFalse(chain.verify("alpha", List.of(a, a)));
    }

    @Test void crossTenantAppendRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> chain.append("beta", "x", "REQUEST", "r2", now, List.of(first())));
    }
}
