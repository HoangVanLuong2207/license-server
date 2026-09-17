import asyncio
import base64
import os
from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError
from starlette.requests import Request

os.environ.setdefault('LICENSE_SIGNING_PRIVATE_KEY', base64.b64encode(b'\x01' * 32).decode())
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin')

import server


@pytest.mark.parametrize('hours', [0.5, 1, 6, 24])
def test_shop_key_duration_and_retry(monkeypatch, hours):
    database = server.Database('', '', '', ':memory:')
    monkeypatch.setattr(server, 'client', database)
    monkeypatch.setattr(server, 'AOVSHOP_ISSUER_TOKEN', 'test-issuer')
    request = Request({'type': 'http', 'headers': [(b'x-aovshop-issuer-token', b'test-issuer')]})

    async def run():
        await database.connect()
        try:
            await database.execute('CREATE TABLE license_keys (key TEXT, created_at TEXT, expires_at TEXT, max_devices INTEGER, note TEXT, source TEXT, external_order_id TEXT, UNIQUE(source, external_order_id))')
            req = server.IssueShopKeyRequest(order_id=1, product_id=1, duration_hours=hours)
            result = await server.issue_checkpass_key_from_aovshop(req, request)
            row = (await database.execute('SELECT created_at, expires_at FROM license_keys')).rows[0]
            assert datetime.fromisoformat(row[1]) - datetime.fromisoformat(row[0]) == timedelta(hours=hours)
            retry = await server.issue_checkpass_key_from_aovshop(req, request)
            assert retry['key'] == result['key']
            assert retry['expires_at'] == result['expires_at']
            assert retry['reused'] is True
            assert (await database.execute('SELECT COUNT(*) FROM license_keys')).rows[0][0] == 1
        finally:
            database.sqlite.close()

    asyncio.run(run())


@pytest.mark.parametrize('hours', [0, -0.5, 8761, float('nan'), float('inf')])
def test_invalid_shop_duration(hours):
    with pytest.raises(ValidationError):
        server.IssueShopKeyRequest(order_id=1, product_id=1, duration_hours=hours)
