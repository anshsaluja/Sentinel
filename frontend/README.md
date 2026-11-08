# Sentinel Angular frontend (early foundation)

Angular 19 standalone application using Keycloak authorization-code flow with PKCE.

## Run locally

1. Start the repository's Keycloak Compose service, set its admin credentials in a local ignored `.env`, and ensure the `sentinel` realm and `sentinel-angular` client are imported.
2. Run `npm install` in this directory, then `npm start`.
3. Visit http://127.0.0.1:4200 and select **Sign in with Keycloak**. Create a local user in Keycloak manually; no credentials are shipped.
4. Use the same loopback hostname for login and callback. The configured issuer is http://localhost:8081/realms/sentinel; the callback uses the page's current origin.

This is an **authentication shell**, not a finished dashboard. It does not fetch or enforce policies, display risk findings, or call approval APIs. All access control must be enforced by the Spring Boot backend using verified JWT claims. The frontend intentionally does not persist access tokens in localStorage.

## Verification

`npm run build` checks Angular compilation. This code has not yet been browser-tested against a running Keycloak instance. The issuer and HTTP allowance are **local-only**; production requires HTTPS and environment-specific configuration.
