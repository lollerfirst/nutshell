from ..core.settings import settings
from ..nostr.client.client import NostrClient
from ..nostr.event import EventKind
from ..core.errors import CashuError
from ..core.base import BlindedSignature, BlindedMessage, Proof
from ..core.models import GetInfoResponse

from typing import List, Union, Any, Tuple
from enum import Enum
from queue import Queue
import asyncio
import cbor2
import base64
import hashlib
import json

from loguru import logger

class MintEvent(Enum):
    MINT = 0
    BURN = 1

class NostrEventPublisher:
    pending_events: List[Any] = []

    def __init__(self, info: GetInfoResponse):
        if settings.mint_private_key is None:
            raise CashuError("No mint private key provided")
        if settings.mint_nostr_relays is None:
            logger.info("No relays specified: using default ones")
        seed = settings.mint_private_key
        relays = settings.mint_nostr_relays or []
        privkey_from_seed = hashlib.sha256(seed.encode("utf-8")).digest()[:32]  # This is how it's generated in `derive_pubkey`
        self.client = NostrClient(privkey_from_seed.hex(), relays)
        
        # Event 11467: CASHU_MINT_IDENTITY
        metadata = base64.b64encode(cbor2.dumps(info.dict())).decode("utf-8")
        self.client.post(metadata, EventKind.CASHU_MINT_IDENTITY)
        self.lock = asyncio.Lock()
        logger.info(f"""
            Set up NostrEventPublisher with public key {self.client.public_key.bech32()}
        """)

    async def publisher(self):
        while True:
            async with self.lock:
                if len(self.pending_events) > 0:
                    # Event 4919: CASHU_DATA
                    try:
                        binary_content = cbor2.dumps(self.pending_events)
                    except Exception as e:
                        logger.error(f"Couldn't serialize pending_events object: {str(e)}")
                    b64_encoded = base64.b64encode(binary_content).decode("utf-8")
                    self.client.post(b64_encoded, EventKind.CASHU_DATA)
                    logger.info(f"Published {len(self.pending_events)} pending events")
                    self.pending_events = []
            await asyncio.sleep(5)
    
    async def add_event(
        self,
        epoch: int,
        mint_event: MintEvent,
        contents: Union[List[Tuple[BlindedSignature, BlindedMessage]], List[Proof]]
    ):
        async with self.lock:
            data = []
            for el in contents:
                if mint_event == MintEvent.MINT:
                    data.append(
                        {
                            'C_': el[0].C_,
                            'B_': el[1].B_,
                            'amount': el[0].amount,
                        }
                    )
                elif mint_event == MintEvent.BURN:
                    assert isinstance(el, Proof)
                    data.append(
                        {
                            'Y': el.Y,
                            'amount': el.amount,
                        }
                    )
            self.pending_events.append({
                'epoch': epoch,
                'event': mint_event.name,
                'contents': data,
            })
            logger.info(f"Added {mint_event.name} event with {len(contents)} contents for epoch {epoch}")