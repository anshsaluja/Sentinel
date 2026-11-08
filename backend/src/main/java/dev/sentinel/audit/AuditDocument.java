package dev.sentinel.audit;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Durable representation of a hash-chain event. The compound unique index
 * prevents duplicate sequence numbers within a tenant, including concurrent
 * writers attempting to append the same next event.
 *
 * A unique index alone does not make approval + audit writes atomic.
 */
@Document(collection = "audit_events")
@CompoundIndex(name = "tenant_sequence_unique", def = "{'tenantId': 1, 'sequence': 1}", unique = true)
public class AuditDocument {
    @Id public String id;
    public String tenantId;
    public long sequence;
    public Instant occurredAt;
    public String actorId;
    public String action;
    public String targetId;
    public String previousHash;
    public String hash;

    public AuditDocument() {}

    public AuditDocument(AuditChain.Event event) {
        this.tenantId = event.tenantId();
        this.sequence = event.sequence();
        this.occurredAt = event.occurredAt();
        this.actorId = event.actorId();
        this.action = event.action();
        this.targetId = event.targetId();
        this.previousHash = event.previousHash();
        this.hash = event.hash();
    }

    public AuditChain.Event toDomain() {
        return new AuditChain.Event(tenantId, sequence, occurredAt, actorId,
                action, targetId, previousHash, hash);
    }
}
