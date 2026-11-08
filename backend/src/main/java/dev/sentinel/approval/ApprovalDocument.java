package dev.sentinel.approval;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Mongo persistence representation. Tenant and request ID are both required
 * for every read/write; the record is never trusted as an authorization source.
 */
@Document(collection = "access_approvals")
@CompoundIndex(name = "tenant_status", def = "{'tenantId': 1, 'status': 1}")
public class ApprovalDocument {
    @Id public String id;
    public String tenantId;
    public String requesterId;
    public String approverId;
    public String resourceId;
    public String justification;
    public ApprovalWorkflow.Status status;
    @Version public Long version;
    public Instant updatedAt;

    public ApprovalDocument() {}

    public ApprovalDocument(ApprovalWorkflow.Request request) {
        id = request.id();
        tenantId = request.tenantId();
        requesterId = request.requesterId();
        approverId = request.approverId();
        resourceId = request.resourceId();
        justification = request.justification();
        status = request.status();
        version = request.version();
        updatedAt = request.updatedAt();
    }

    public ApprovalWorkflow.Request toDomain() {
        if (version == null) throw new IllegalStateException("Missing approval version");
        return new ApprovalWorkflow.Request(id, tenantId, requesterId, approverId,
                resourceId, justification, status, version, updatedAt);
    }
}
