# Sentinel Angular frontend (local development)

Angular 19 standalone workspace using Keycloak authorization-code flow with PKCE. The UI supports authenticated policy evaluation and simulation previews, sample access-risk analysis/comparison, access-request submission, and a reviewer approval queue with optimistic-version decisions. The policy/risk inputs are illustrative; **these previews are not authorization enforcement or live directory scans**. The backend is responsible for JWT validation, tenant isolation, authorization, and persisted audit events.

## Local prerequisites

- Node.js 22 and npm, plus the repository's Java 21/Spring Boot API.
- Docker Compose services from the repository root: MongoDB 7 replica set and Keycloak 26, configured with unique credentials in the ignored `.env` file.
- Initialize MongoDB transactions with `bash scripts/init-mongo-replica.sh` from the repository root.
- Start the backend with `SENTINEL_OIDC_ISSUER_URI=http://localhost:8081/realms/sentinel` and `SPRING_DATA_MONGODB_URI='mongodb://localhost:27017/sentinel?replicaSet=rs0'` in its environment.
- Create local requester and reviewer accounts in the imported `sentinel` realm, assigning reviewer privileges only to the reviewer. The realm import does not ship user passwords.

## Run and verify

From `frontend/`:

```sh
npm install --no-audit --no-fund
npm test
npm run build
npm start
```

Visit `http://localhost:4200` and sign in with Keycloak. The configured issuer is `http://localhost:8081/realms/sentinel`; the OAuth callback uses the browser origin. Keep the configured Keycloak client redirect origins aligned with the host used in the browser.

**Dependency reproducibility limitation:** This frontend currently has no committed `package-lock.json`, so `npm ci` will fail in a clean checkout. Use `npm install` until a lockfile has been generated, reviewed, committed, and verified. The frontend CI workflow likewise currently uses `npm install`.

**Test coverage limitation:** `npm test` runs Node-based API transport regressions against the actual TypeScript transport. `npm run build` checks Angular compilation. The existing `npm run test:angular` command is **not operational** until an Angular test builder, runner dependencies, and a test target are configured. Passing the transport tests or compilation does not demonstrate component behavior or authenticated end-to-end integration.

## Guided local walkthrough

1. Sign in as requester. Submit a resource and business justification; the request should be pending, not grant access. Confirm the backend derives requester and tenant from the access token rather than browser-controlled fields.
2. Sign in as reviewer. Refresh the pending queue and approve or reject a request. Verify the expected-version check, the persisted decision, and its audit record in MongoDB.
3. Repeat a decision using a stale version and verify a conflict; test a separate tenant with appropriately configured tokens and confirm isolation.
4. Try policy and risk previews only as sample-data demonstrations. They do not read an organization's live directory or authorize real resource access.
5. Record actual HTTP responses, MongoDB results, and test commands. The full Keycloak–Spring Boot–MongoDB–Angular flow has not yet been verified in this development environment.

This is a loopback-only development setup. Never publish its HTTP issuer, credentials, or services on a public host; never commit `.env`, access tokens, or passwords. For full service setup and outstanding verification work, see the [root README](../README.md).
