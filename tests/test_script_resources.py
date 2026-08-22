import asyncio
import base64
import json
import os

import pytest
from fastapi import HTTPException
from starlette.requests import Request


os.environ.setdefault("LICENSE_SIGNING_PRIVATE_KEY", base64.b64encode(b"\x01" * 32).decode())
os.environ.setdefault("ADMIN_PASSWORD", "test-admin")

import server


KEY = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"
HWID = "A" * 32


class Result:
    def __init__(self, rows, columns=()):
        self.rows = rows
        self.columns = columns


class ResourceDB:
    def __init__(self):
        self.writes = []

    async def execute(self, sql, args=()):
        compact = " ".join(sql.split())
        if compact.startswith("SELECT hwid, expires_at, is_active"):
            return Result([(HWID, None, 1)])
        if compact.startswith("SELECT name, content FROM flow_scripts"):
            return Result([("one.json", '[{"action":"wait"}]')])
        if compact.startswith("SELECT sha256 FROM flow_scripts"):
            digest = server.hashlib.sha256('[{"action":"wait"}]'.encode()).hexdigest()
            return Result([(digest,)])
        if compact.startswith("SELECT COUNT(*) FROM flow_scripts"):
            return Result([(1,)])
        self.writes.append((compact, args))
        return Result([])


def request():
    return Request({"type": "http", "client": ("127.0.0.1", 1234), "headers": []})


def decode_payload(token):
    encoded = token.split(".", 1)[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def test_bundle_requires_bound_license_and_returns_signed_claims(monkeypatch):
    monkeypatch.setattr(server, "client", ResourceDB())
    req = server.ScriptAccessRequest(key=KEY, hwid=HWID, nonce="N" * 24)
    response = asyncio.run(server.download_script_bundle(req, request()))

    assert response["scripts"] == {"one.json": [{"action": "wait"}]}
    payload = decode_payload(response["attestation"])
    assert payload["kind"] == "script_bundle"
    assert payload["script_count"] == 1
    assert payload["hwid"] == HWID


def test_ping_exposes_script_readiness_for_release_gate(monkeypatch):
    monkeypatch.setattr(server, "client", ResourceDB())
    response = asyncio.run(server.ping())
    assert response["script_api"] == 1
    assert response["scripts_ready"] is True
    assert response["script_count"] == 1


def test_each_script_authorization_returns_hash_bound_ticket(monkeypatch):
    monkeypatch.setattr(server, "client", ResourceDB())
    req = server.ScriptAccessRequest(key=KEY, hwid=HWID, nonce="Z" * 24)
    response = asyncio.run(server.authorize_script_run("one.json", req, request()))

    payload = decode_payload(response["ticket"])
    assert response["authorized"] is True
    assert payload["kind"] == "script_run"
    assert payload["script_name"] == "one.json"
    assert len(payload["script_hash"]) == 64


def test_resource_access_rejects_wrong_hwid(monkeypatch):
    monkeypatch.setattr(server, "client", ResourceDB())
    with pytest.raises(HTTPException, match="thiết bị"):
        asyncio.run(server._require_bound_license(KEY, "B" * 32))


def test_admin_sync_normalizes_and_hashes_scripts(monkeypatch):
    database = ResourceDB()
    monkeypatch.setattr(server, "client", database)
    req = server.ScriptSyncRequest(
        admin_password="test-admin",
        scripts=[server.ScriptSyncItem(name="one.json", content=[{"action": "wait"}])],
    )
    response = asyncio.run(server.sync_scripts(req))

    assert response == {"synced": 1, "replace_all": True}
    assert any("ON CONFLICT(name) DO UPDATE" in sql for sql, _ in database.writes)
