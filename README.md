# Sentinel — Access Risk & Policy Simulation

Focused portfolio project for explaining and predicting access changes, not a full identity management product.

## Implemented (runtime verification still required)

- Pure Java deny-by-default RBAC + attribute-equality ABAC evaluator with explicit-deny precedence.
- Read-only, deterministic before/after policy simulation.
- Risk finding engine and associated unit tests (see backend sources).
- Spring Boot REST policy/risk preview endpoints protected by JWT resource-server authentication.
- Tenant-scoped MongoDB approval-request creation, queue and detail reads, reviewer/admin approve/reject API, optimistic version checks, and transactional audit-chain writes (not yet runtime-verified).
- Angular PKCE sign-in, sample policy/risk explorers, and a reviewer approval queue with confirmation and conflict handling.
- API derives tenant context from the verified JWT `tenant_id` claim; mismatched tenant inputs are rejected.
- JUnit unit tests and MockMvc authentication/tenant-isolation test source.

**Security boundary:** Both preview endpoints currently accept policy rules supplied by the caller. They are **not authorization enforcement endpoints** and MUST NOT be used to authorize real access. The tenant claim must be issued by a trusted Keycloak realm, not an untrusted caller. Future production enforcement will load policies from tenant-scoped MongoDB persistence.

## Local backend setup

Requires Java 21, Maven, and a running OIDC issuer such as Keycloak.

1. Configure a Keycloak realm with issuer URI and a trusted client; include a verified `tenant_id` claim in access tokens.
2. Export `SENTINEL_OIDC_ISSUER_URI` to the issuer URL (default: `http://localhost:8081/realms/sentinel`).
3. In `backend/`, run `mvn verify` then `mvn spring-boot:run`.
4. POST `/api/v1/policies/evaluate` or `/api/v1/policies/simulate` with `Authorization: Bearer <access-token>`. There are no anonymous demo endpoints.

### Evaluation example

```json
{
  "request": {"tenantId":"alpha","resourceId":"ledger","action":"read","roles":["analyst"],"attributes":{"department":"finance"}},
  "rules": [{"tenantId":"alpha","resourceId":"ledger","action":"read","roles":["analyst"],"attributes":{"department":"finance"},"effect":"ALLOW"}]
}
```

For simulation, send `{"subjects":[{"userId":"alice","request":{...}}],"before":[...],"after":[...]}`, where all tenant IDs equal the authenticated token's `tenant_id`.

## MongoDB-backed trusted policy foundation

Tenant-scoped policy persistence is now implemented in `StoredPolicy`, `PolicyRepository`, and `TrustedPolicyService`. The service retrieves enabled rules from MongoDB using tenant/resource/action filters and fails closed if a repository returns foreign-tenant data. The legacy preview endpoints **still accept caller-supplied rules**; the trusted service is not yet connected to an authenticated enforcement endpoint. The local `compose.yaml` starts MongoDB and imports a `sentinel` Keycloak realm on first startup. It does not create test users or credentials.

For local services, copy `.env.example` to `.env`, supply a unique `KEYCLOAK_ADMIN_PASSWORD`, and run `docker compose up -d`. **Before running transactional approval flows**, initialize the MongoDB single-node replica set with `bash scripts/init-mongo-replica.sh` from the repository root. The script is idempotent and waits for primary election. MongoDB transactions fail on a standalone server. The local replica-set member uses `localhost:27017`, matching the backend running on the host; do not use this topology for a backend running in a separate container without adapting replica-set discovery and networking. Set `SPRING_DATA_MONGODB_URI=mongodb://localhost:27017/sentinel?replicaSet=rs0` in the backend environment. These commands have not been executed in this development environment because Docker is unavailable. The `sentinel` realm is imported on first Keycloak startup from `keycloak/sentinel-realm.json`. The realm defines a public `sentinel-local-cli` OIDC authorization-code client with required S256 PKCE, a `tenant_id=local-demo` access-token claim, and reviewer/admin realm roles. Create test users manually in the local Keycloak admin console and assign roles only as needed. No test passwords are committed. Realm import is skipped if a realm of the same name already exists; remove/reconfigure the existing realm deliberately if testing import changes. The hardcoded local-demo tenant mapper is for development only, not production multi-tenancy. The CLI callback is restricted to localhost port 8765. A separate public `sentinel-angular` client supports an Angular development server on localhost/127.0.0.1 port 4200, with authorization-code flow and required S256 PKCE. Its redirect patterns allow paths only on those loopback origins; narrow them to the exact callback route when the Angular router is implemented. Both clients are development-only. Run `python3 -m unittest discover -s scripts -p 'test_*.py'` to validate the realm's security invariants without starting Docker. This is static validation, not proof of Keycloak import, token issuance, or Angular integration. This realm import has not been runtime-verified because Docker is unavailable. Do not use this development Compose stack on a public host. `mvn verify` requires a running MongoDB instance for Spring application-context tests.

## Verification and remaining MVP work

- Run `cd backend && mvn verify` with the MongoDB replica set available; verify transaction, audit-chain, HTTP security and approval controller tests.
- Run `cd frontend && npm ci && npm test && npm run build` to verify the Angular client and transport regressions.
- Run `python3 -m unittest discover -s scripts -p 'test_*.py'` for static Keycloak realm checks.
- Verify the real Keycloak login and reviewer role, Angular queue GET preflight, approval decision POST, MongoDB transaction, and audit integrity in one local walkthrough.
- Exercise `POST /api/v1/approval-requests` with a JWT-authenticated requester; confirm tenant and requester are taken from JWT claims, not caller-controlled JSON. Verify that a new request is `PENDING` and its creation audit event is committed in the same MongoDB transaction. The endpoint and tests are committed but have not yet been compiled or runtime-verified. There is currently no end-user request creation UI.
- Check that an unauthenticated creation request is rejected, a requester cannot impersonate another tenant, and reviewer decisions reject stale versions; repeat against a running MongoDB replica set.
- Improve the dashboard and guided demo, and keep CI green before calling the MVP complete.

**Important:** The policy evaluation and risk exploration screens use caller-supplied/sample data; they are not live directory scanning or authorization enforcement. The approval workflow is persisted separately. Elasticsearch and gRPC remain deferred.

## Status and safeguards

Do not claim CI green until the GitHub Actions workflow has actually passed for the current commit. No secrets committed; no public deployment or paid services. Elasticsearch and gRPC are deferred unless real requirements justify their complexity.
