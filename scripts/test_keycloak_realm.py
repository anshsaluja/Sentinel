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
            {"http://localhost:4200/*", "http://127.0.0.1:4200/*"},
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


if __name__ == "__main__":
    unittest.main()
