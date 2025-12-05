# Mirror tests for src/drcom_core/core.py
import pytest
from unittest.mock import AsyncMock

from drcom_core.core import DrcomCore
from drcom_core.state import CoreStatus


@pytest.mark.asyncio
async def test_core_step_success(valid_config):
    core = DrcomCore(valid_config)
    core.state.status = CoreStatus.LOGGED_IN
    core.protocol.keep_alive = AsyncMock(return_value=True)
    ok = await core.step()
    assert ok is True


@pytest.mark.asyncio
async def test_core_probe_server(valid_config, monkeypatch):
    core = DrcomCore(valid_config)

    async def fake_probe(timeout: float) -> bool:
        return True

    monkeypatch.setattr(core.protocol, "probe", fake_probe)
    assert await core.probe_server(1.0) is True
