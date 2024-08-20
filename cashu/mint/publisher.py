from ..core.settings import settings
from ..nostr.client.client import NostrClient
from ..nostr.event import EventKind
from ..core.errors import CashuError
from ..core.base import BlindedSignature, Proof

from typing import List, Union, Any
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

    def __init__(self):
        if settings.mint_private_key is None:
            raise CashuError("No mint private key provided")
        if settings.mint_nostr_relays is None:
            logger.info("No relays specified: using default ones")
        logger.debug("Poke")
        seed = settings.mint_private_key
        relays = settings.mint_nostr_relays or []
        privkey_from_seed = hashlib.sha256(seed.encode("utf-8")).digest()[:32]  # This is how it's generated in `derive_pubkey`
        self.client = NostrClient(privkey_from_seed.hex(), relays)
        # Set metadata for the profile
        metadata = json.dumps({
            'name': settings.mint_nostr_name or "cashu mint",
            'about': settings.mint_info_description or "",
            'picture': ''
        })
        self.client.post(metadata, EventKind.SET_METADATA)
        self.lock = asyncio.Lock()
        logger.debug(f"Set up NostrEventPublisher with public key {self.client.public_key.bech32()}\nor hex equivalent: {self.client.public_key.hex()}")

    async def publisher(self):
        while True:
            async with self.lock:
                if len(self.pending_events) > 0:
                    logger.debug("Poke!")
                    try:
                        binary_content = cbor2.dumps(self.pending_events)
                    except Exception as e:
                        logger.error(f"Couldn't serialize pending_events object: {str(e)}")
                    b64_encoded = base64.b64encode(binary_content).decode('utf-8')
                    self.client.post(b64_encoded, EventKind.TEXT_NOTE)
                    logger.info(f"Published {len(self.pending_events)} pending events")
                    self.pending_events = []
            await asyncio.sleep(5)
    
    async def add_event(
        self,
        epoch: int,
        mint_event: MintEvent,
        contents: Union[List[BlindedSignature], List[Proof]]
    ):
        async with self.lock:
            self.pending_events.append({
                'epoch': epoch,
                'event': mint_event.name,
                'contents': [c.C if isinstance(c, Proof) else c.C_ for c in contents]
            })
            logger.info(f"Added {mint_event.name} event with {len(contents)} contents for epoch {epoch}")