import asyncio

import pytest

from cashu.core.models import PostCheckRequest
from cashu.mint.ledger import Ledger

'''
@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1
'''

indices = [30794081, 8327865, 23705171, 52653350, 62689960, 6329467, 44846055, 14757982, 52449606, 16582630, 24918498, 7806512, 42347175, 41195189, 49015787, 55816314, 53746619, 3355535, 57785090, 50046961, 36831346, 13456785, 20047490, 44404213, 26938763, 43324235, 18566427, 34892005, 3189684, 38319682, 9512967, 33431787, 25346186, 32527125, 21461078, 58248452, 25688048, 24175824, 42292653, 42233964, 55552215, 64372537, 36983200, 52251711, 4175312, 30579061, 1106663]

@pytest.mark.asyncio
async def test_get_k_indices(ledger: Ledger):
    bloomf = ledger.bloomf
    secret = "testing"
    result = await bloomf.get_k_indices(secret)
    print(f"{indices = }")
    assert result == indices

@pytest.mark.asyncio
async def test_add_and_check(ledger: Ledger):
    bloomf = ledger.bloomf
    secret = "testing"
    await bloomf.add_elements([secret])
    response = await ledger.check_indices(PostCheckRequest(indices=indices))
    assert all([d == 1 for _, d in response.result])

@pytest.mark.asyncio
async def test_filter_sliding(ledger: Ledger):
    bloomf = ledger.bloomf
    bloomf.i = 500000-1
    secret = "testing"
    await bloomf.add_elements([secret])
    await asyncio.sleep(2)
    assert bloomf.i == 0
    response = await ledger.check_indices(PostCheckRequest(indices=indices))
    assert all([d == 1 for _, d in response.result])