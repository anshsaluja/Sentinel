package dev.sentinel.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** Tamper-evident, tenant-bound append-only audit event hash chain. */
public final class AuditChain {
    public static final String GENESIS = "GENESIS";
    public record Event(String tenantId, long sequence, Instant occurredAt, String actorId,
                        String action, String targetId, String previousHash, String hash) {
        public Event {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(occurredAt);
            Objects.requireNonNull(actorId);
            Objects.requireNonNull(action);
            Objects.requireNonNull(targetId);
            Objects.requireNonNull(previousHash);
            Objects.requireNonNull(hash);
        }
    }

    public Event append(String tenantId, String actorId, String action, String targetId,
                        Instant occurredAt, List<Event> existing) {
        requireNonblank(tenantId);
        requireNonblank(actorId);
        requireNonblank(action);
        requireNonblank(targetId);
        Objects.requireNonNull(occurredAt);
        Objects.requireNonNull(existing);
        if (!verify(tenantId, existing)) throw new IllegalArgumentException("Invalid existing audit chain");
        Event last = existing.isEmpty() ? null : existing.get(existing.size() - 1);
        long next = last == null ? 1 : Math.addExact(last.sequence(), 1);
        String previous = last == null ? GENESIS : last.hash();
        return new Event(tenantId, next, occurredAt, actorId, action, targetId, previous,
                digest(tenantId, next, occurredAt, actorId, action, targetId, previous));
    }

    public boolean verify(String tenantId, List<Event> events) {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(events);
        String previous = GENESIS;
        long sequence = 1;
        for (Event event : events) {
            if (event == null || !tenantId.equals(event.tenantId()) || event.sequence() != sequence
                    || !previous.equals(event.previousHash())
                    || !digest(event.tenantId(), event.sequence(), event.occurredAt(),
                        event.actorId(), event.action(), event.targetId(), event.previousHash()).equals(event.hash())) {
                return false;
            }
            previous = event.hash();
            sequence++;
        }
        return true;
    }

    private static void requireNonblank(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Audit field required");
    }

    private static String digest(String tenantId, long sequence, Instant at, String actor,
                                 String action, String target, String previous) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Length-prefixed fields prevent ambiguous concatenations.
            for (String field : List.of(tenantId, Long.toString(sequence), at.toString(), actor,
                    action, target, previous)) {
                byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
                md.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array());
                md.update(bytes);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
