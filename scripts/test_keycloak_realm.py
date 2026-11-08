#!/usr/bin/env python3
"""Validate the checked-in local Keycloak realm without external dependencies."""
import json
import pathlib
import unittest

REALM_PATH = pathlib.Path(__file__).resolve().parents[1] / "keycloak" / "sentinel-realm.json"


class RealmSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realm = json.loads(REALM_PATH.read_text(encoding="utf-8"))
        cls.clients = {client["clientId"]: client for client in cls.realm["clients"]}

    def test_login_brute_force_protection_is_bounded(self):
        self.assertTrue(self.realm["bruteForceProtected"])
        self.assertFalse(self.realm["permanentLockout"])
        self.assertEqual(self.realm["failureFactor"], 5)
        self.assertGreaterEqual(self.realm["waitIncrementSeconds"], 30)
        self.assertLessEqual(self.realm["maxFailureWaitSeconds"], 900)

    def test_realm_and_clients_are_enabled(self):
        self.assertEqual(self.realm["realm"], "sentinel")
        self.assertTrue(self.realm["enabled"])
        self.assertIn("sentinel-angular", self.clients)
        self.assertIn("sentinel-local-cli", self.clients)
        self.assertEqual(len(self.clients), len(self.realm["clients"]))

    def test_public_clients_require_pkce_and_disallow_password_grant(self):
        for client in self.clients.values():
            with self.subTest(client=client["clientId"]):
                self.assertTrue(client["enabled"])
                self.assertTrue(client["publicClient"])
                self.assertTrue(client["standardFlowEnabled"])
                self.assertFalse(client["directAccessGrantsEnabled"])
                self.assertFalse(client["implicitFlowEnabled"])
                self.assertFalse(client["serviceAccountsEnabled"])
                self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
                self.assertNotIn("secret", client)

    def test_angular_redirects_and_origins_are_local_only(self):
        client = self.clients["sentinel-angular"]
        self.assertEqual(
            set(client["redirectUris"]),
            {"http://localhost:4200/", "http://127.0.0.1:4200/"},
        )
        self.assertEqual(
            set(client["webOrigins"]),
            {"http://localhost:4200", "http://127.0.0.1:4200"},
        )
        self.assertNotIn("*", client["webOrigins"])
        self.assertNotIn("*", client["redirectUris"])

    def test_tenant_claim_is_access_token_only(self):
        scope = next(s for s in self.realm["clientScopes"] if s["name"] == "sentinel-tenant")
        mapper = next(m for m in scope["protocolMappers"] if m["name"] == "tenant-id")
        config = mapper["config"]
        self.assertEqual(config["claim.name"], "tenant_id")
        self.assertEqual(config["access.token.claim"], "true")
        self.assertEqual(config["id.token.claim"], "false")
        for client in self.clients.values():
            self.assertIn("sentinel-tenant", client["defaultClientScopes"])

    def test_cli_callback_is_exact_and_browser_origins_are_disabled(self):
        client = self.clients["sentinel-local-cli"]
        self.assertEqual(
            set(client["redirectUris"]),
            {"http://127.0.0.1:8765/callback", "http://localhost:8765/callback"},
        )
        self.assertEqual(client["webOrigins"], [])

    def test_reviewer_and_admin_roles_are_declared(self):
        roles = {role["name"] for role in self.realm["roles"]["realm"]}
        self.assertIn("sentinel-reviewer", roles)
        self.assertIn("sentinel-admin", roles)

    def test_import_contains_no_users_or_client_secrets(self):
        self.assertNotIn("users", self.realm)
        for client in self.clients.values():
            with self.subTest(client=client["clientId"]):
                self.assertNotIn("secret", client)
                self.assertNotIn("clientAuthenticatorType", client)

    def test_tenant_mapper_is_explicitly_local_and_not_in_identity_tokens(self):
        scopes = [scope for scope in self.realm["clientScopes"] if scope["name"] == "sentinel-tenant"]
        self.assertEqual(len(scopes), 1)
        scope = scopes[0]
        self.assertEqual(scope["protocol"], "openid-connect")
        self.assertEqual(len(scope["protocolMappers"]), 1)
        mapper = scope["protocolMappers"][0]
        self.assertEqual(mapper["protocolMapper"], "oidc-hardcoded-claim-mapper")
        config = mapper["config"]
        self.assertEqual(config["claim.value"], "local-demo")
        self.assertEqual(config["jsonType.label"], "String")
        self.assertEqual(config["userinfo.token.claim"], "false")
        self.assertEqual(config["access.token.claim"], "true")
        self.assertEqual(config["id.token.claim"], "false")

    def test_privileged_roles_are_not_granted_by_default(self):
        privileged = {"sentinel-reviewer", "sentinel-admin"}
        default_roles = self.realm.get("defaultRoles", [])
        self.assertTrue(privileged.isdisjoint(default_roles))
        for role in self.realm["roles"]["realm"]:
            if role["name"] in privileged:
                self.assertFalse(role.get("composite", False))
                self.assertFalse(role.get("clientRole", False))
        self.assertNotIn("defaultRole", self.realm)
        for client in self.clients.values():
            self.assertNotIn("defaultRoles", client)

    def test_oauth_clients_do_not_allow_unrestricted_redirects(self):
        for client in self.clients.values():
            with self.subTest(client=client["clientId"]):
                self.assertEqual(client["protocol"], "openid-connect")
                self.assertTrue(client["redirectUris"])
                for uri in client["redirectUris"]:
                    self.assertTrue(uri.startswith(("http://localhost:", "http://127.0.0.1:")))
                    self.assertNotIn("?", uri)
                    self.assertNotIn("#", uri)
                    self.assertNotIn("0.0.0.0", uri)
                    self.assertNotIn("*", uri, "OAuth callback must be an exact URI")
                self.assertNotIn("+", client["webOrigins"])
                self.assertNotIn("*", client["webOrigins"])


if __name__ == "__main__":
    unittest.main()
