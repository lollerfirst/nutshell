import asyncio
import random
import pytest
import pytest_asyncio
from loguru import logger

from tests.conftest import SERVER_ENDPOINT
from cashu.wallet.wallet import Wallet
from cashu.core.models import PostCheckRequest
from cashu.mint.ledger import Ledger
from cashu.core.bloom import get_k_indices

from tests.helpers import pay_if_regtest, get_real_invoice, is_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet.load_mint()
    yield wallet


test_indices = [30794081, 8327865, 23705171, 52653350, 62689960, 6329467, 44846055, 14757982, 52449606, 16582630, 24918498, 7806512, 42347175, 41195189, 49015787, 55816314, 53746619, 3355535, 57785090, 50046961, 36831346, 13456785, 20047490, 44404213, 26938763, 43324235, 18566427, 34892005, 3189684, 38319682, 9512967, 33431787, 25346186, 32527125, 21461078, 58248452, 25688048, 24175824, 42292653, 42233964, 55552215, 64372537, 36983200, 52251711, 4175312, 30579061, 1106663]

@pytest.mark.asyncio
async def test_get_k_indices(ledger: Ledger):
    bloomf = ledger.bloomf
    secret = "testing"
    k = 47
    m = 67095409
    result = await get_k_indices(secret, k, m)
    assert result == test_indices

@pytest.mark.asyncio
async def test_add_and_check(ledger: Ledger):
    bloomf = ledger.bloomf
    secret = "testing"
    await bloomf.add_elements([secret])
    response = await ledger.check_indices(PostCheckRequest(indices=test_indices))
    assert all([v == 1 for v in response.result.values()])

@pytest.mark.asyncio
async def test_filter_sliding(ledger: Ledger):
    bloomf = ledger.bloomf
    bloomf.i = bloomf.n-1
    secret = "testing"
    await bloomf.add_elements([secret])
    await asyncio.sleep(2)
    assert bloomf.i == 0
    assert all([b == 0 for b in bloomf.filter_curr])
    
@pytest.mark.asyncio
async def test_mint_melt_check(wallet: Wallet, ledger: Ledger):
    if is_regtest:
        pytest.skip("")

    # Alice (Mints and sends to Bob)
    invoice = await wallet.request_mint(10)
    await pay_if_regtest(invoice.bolt11)
    proofs = await wallet.mint(10, id=invoice.id)

    # Bob (redeems)
    payment_request = (
        "lnbc10n1pjaxujrpp5sqehn6h5p8xpa0c0lvj5vy3a537gxfk5e7h2ate2alfw3y5cm6xqdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
        "p5fkxsvyl0r32mvnhv9cws4rp986v0wjl2lp93zzl8jejnuwzvpynq9qyyssqqmsnatsz87qrgls98c97dfa6l2z3rzg2x6kxmrvpz886rwjylmd56y3qxzfulrq03kkh"
        "hwk6r32wes6pjt2zykhnsjn30c6uhuk0wugp3x74al"
    ) # 1 sat
    quote = await wallet.melt_quote(payment_request)
    status = await wallet.melt(proofs, payment_request, 0, quote.quote)
    assert status.paid and status.paid == True

    # Alice (Checks if secrets are burnt after some time)
    await asyncio.sleep(2)
    # bloom filter parameters (AGREED UPON ON SPEC)
    k = 47
    m = 67095409
    indices = [await get_k_indices(p.secret, k, m) for p in proofs]
    indices = [item for sublist in indices for item in sublist]
    # add some random indices to throw off tracking tactics
    salt = [random.randint(0, m-1) for _ in range(len(indices))]
    send_indices = indices+salt
    random.shuffle(send_indices)
    # request mint
    result = await ledger.check_indices(PostCheckRequest(indices=send_indices))
    assert len(result.result.items()) > 0, "Empty resultset"
    assert all([result.result[index] == 1 for index in indices])