import asyncio
import os
import pickle
from typing import List, Tuple, Dict

import mmh3
from bitarray import bitarray
from loguru import logger

from .settings import settings

async def get_k_indices(element: str, k: int, m: int = 2**32) -> List[int]:
    indices = []
    for seed in range(k):
        # CAN WE RELY ON MURMURHASH DIFFUSION?
        index = mmh3.hash(element, seed, signed=False)  # returns a unsigned 32-bits number. More than enough for out purposes.
        index %= m
        indices.append(index)
    return indices

# https://hur.st/bloomfilter/?n=1000000&p=&m=67095409&k=47
class SlidingBloomFilter:
    m: int = 67095409           # number of bits for one filter
    n: int = (1000000 // 2)     # number of maximum allowed elements for one filter
    i: int = 0                  # enumeration of the next element to be added
    k: int = 47                 # number of hash functions
    elements_added: bool = False
    # FPR ~= 1E-14 --> we OR the truth values of old filter with current filter, which effectively
    # makes it as if the current filter already had `n` entries. Therefore, we halve the number of entries
    # we are allowed to insert to keep the FPR the same.

    def __init__(self):
        filter_path = settings.mint_bloom_filter
        assert os.path.exists(filter_path), f"{filter_path} does not exist."
        self.filter_old_path = os.path.join(filter_path, 'mint.filter.old')
        self.filter_curr_path = os.path.join(filter_path, 'mint.filter.current')

        if os.path.exists(self.filter_old_path):
            try:
                with open(self.filter_old_path, 'rb') as f:
                    self.filter_old = pickle.load(f)
            except Exception as e:
                logger.error(f"Error loading old filter: {str(e)}")
                raise e
        else:
            self.filter_old = bitarray(self.m)
            with open(self.filter_old_path, 'wb') as f:
                pickle.dump(self.filter_old, f)

        if os.path.exists(self.filter_curr_path):
            try:
                with open(self.filter_curr_path, 'rb') as f:
                    self.filter_curr = pickle.load(f)
                    logger.debug(f"{type(self.filter_curr) = }")
            except Exception as e:
                logger.error(f"Error loading current filter: {str(e)}")
                raise e
        else:
            self.filter_curr = bitarray(self.m)
            with open(self.filter_curr_path, 'wb') as f:
                pickle.dump(self.filter_curr, f)
        
        # Lock
        self.lock = asyncio.Lock()

        # Persistence
        self.persist_task = asyncio.create_task(self.persist())
        #self.shutdown_event = asyncio.Event()

        logger.info("Sliding Bloom filter correctly initialized")
        
    async def persist(self):
        while True:
            logger.debug("I am awake")
            async with self.lock:
                logger.debug("Lock acquired")
                if self.elements_added:
                    logger.info("Persisting filter elements")
                    if self.i >= self.n:
                        logger.info("Current filter is too large: sliding...")
                        del self.filter_old
                        self.filter_old = self.filter_curr
                        self.filter_curr = bitarray(self.m)
                        self.i = 0
                    try:
                        with open(self.filter_curr_path, 'wb') as f:
                            pickle.dump(self.filter_curr, f)
                        with open(self.filter_old_path, 'wb') as f:
                            pickle.dump(self.filter_old, f)
                    except Exception as e:
                        logger.error(f"Couldn't persist: {str(e)}")
                    self.elements_added = False
                logger.debug("Releasing lock...")
            await asyncio.sleep(2)

    async def get_values(self, indices: List[int]) -> Dict[int, int]:
        assert all([i >= 0 for i in indices]), "Some indices are negative"
        result = {}
        async with self.lock:
            for i in indices:
                i %= self.m
                result[i] = self.filter_curr[i] | self.filter_old[i]
                logger.debug(f"{self.filter_curr[i] = } {i = }")
        return result

    async def add_elements(self, elements: List[str]) -> None:
        async with self.lock:
            for el in elements:
                indices = await get_k_indices(el, self.k, self.m)
                for index in indices:
                    self.filter_curr[index] = 1
                    logger.debug(f"{self.filter_curr[index] = } {index = }")
            self.i += len(elements)
            self.elements_added = True
        logger.info(f"Inserted {len(elements)} elements in the filter")