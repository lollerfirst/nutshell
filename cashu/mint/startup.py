# startup routine of the standalone app. These are the steps that need
# to be taken by external apps importing the cashu mint.

import asyncio
import importlib
import os
from copy import copy
from pathlib import Path
from typing import Dict, List

from loguru import logger

import cashu.mint.management_rpc.management_rpc as management_rpc

from ..core.base import Method, Unit
from ..core.db import Database
from ..core.migrations import migrate_databases
from ..core.settings import settings
from ..lightning.base import LightningBackend
from ..lightning.plugins import initialize_plugin_system, create_backend_instance
from ..mint import migrations as mint_migrations
from ..mint.auth import migrations as auth_migrations
from ..mint.auth.server import AuthLedger
from ..mint.crud import LedgerCrudSqlite
from ..mint.ledger import Ledger

# kill the program if python runs in non-__debug__ mode
# which could lead to asserts not being executed for optimized code
if not __debug__:
    raise Exception("Nutshell cannot run in non-debug mode.")

logger.debug("Enviroment Settings:")
for key, value in settings.dict().items():
    if key in [
        "mint_private_key",
        "mint_seed_decryption_key",
        "nostr_private_key",
        "mint_lnbits_key",
        "mint_blink_key",
        "mint_strike_key",
        "mint_lnd_rest_macaroon",
        "mint_lnd_rest_admin_macaroon",
        "mint_lnd_rest_invoice_macaroon",
        "mint_corelightning_rest_macaroon",
        "mint_clnrest_rune",
    ]:
        value = "********" if value is not None else None

    if key == "mint_database" and value and value.startswith("postgres://"):
        value = "postgres://********"

    logger.debug(f"{key}: {value}")

# Initialize plugin system
plugin_dirs = []
if settings.mint_plugin_dirs:
    plugin_dirs.extend(settings.mint_plugin_dirs)
initialize_plugin_system(plugin_dirs)

backends: Dict[Method, Dict[Unit, LightningBackend]] = {}
if settings.mint_backend_bolt11_sat:
    backend_bolt11_sat = create_backend_instance(settings.mint_backend_bolt11_sat, unit=Unit.sat)
    if backend_bolt11_sat:
        backends.setdefault(Method.bolt11, {})[Unit.sat] = backend_bolt11_sat
    else:
        raise Exception(f"Backend not found: {settings.mint_backend_bolt11_sat}")
if settings.mint_backend_bolt11_msat:
    backend_bolt11_msat = create_backend_instance(settings.mint_backend_bolt11_msat, unit=Unit.msat)
    if backend_bolt11_msat:
        backends.setdefault(Method.bolt11, {})[Unit.msat] = backend_bolt11_msat
    else:
        raise Exception(f"Backend not found: {settings.mint_backend_bolt11_msat}")
if settings.mint_backend_bolt11_usd:
    backend_bolt11_usd = create_backend_instance(settings.mint_backend_bolt11_usd, unit=Unit.usd)
    if backend_bolt11_usd:
        backends.setdefault(Method.bolt11, {})[Unit.usd] = backend_bolt11_usd
    else:
        raise Exception(f"Backend not found: {settings.mint_backend_bolt11_usd}")
if settings.mint_backend_bolt11_eur:
    backend_bolt11_eur = create_backend_instance(settings.mint_backend_bolt11_eur, unit=Unit.eur)
    if backend_bolt11_eur:
        backends.setdefault(Method.bolt11, {})[Unit.eur] = backend_bolt11_eur
    else:
        raise Exception(f"Backend not found: {settings.mint_backend_bolt11_eur}")
if not backends:
    raise Exception("No backends are set.")

if not settings.mint_private_key:
    raise Exception("No mint private key is set.")

ledger = Ledger(
    db=Database("mint", settings.mint_database),
    seed=settings.mint_private_key,
    seed_decryption_key=settings.mint_seed_decryption_key,
    derivation_path=settings.mint_derivation_path,
    backends=backends,
    crud=LedgerCrudSqlite(),
)

# start auth ledger
auth_ledger = AuthLedger(
    db=Database("auth", settings.mint_auth_database),
    seed="auth seed here",
    amounts=[1],
    derivation_path="m/0'/999'/0'",
    crud=LedgerCrudSqlite(),
)


async def rotate_keys(n_seconds=60):
    """Rotate keyset epoch every n_seconds.
    Note: This is just a helper function for testing purposes.
    """
    i = 0
    while True:
        i += 1
        logger.info("Rotating keys.")
        incremented_derivation_path = (
            f"{'/'.join(ledger.derivation_path.split('/')[:-1])}/{i}"
        )
        await ledger.activate_keyset(derivation_path=incremented_derivation_path)
        logger.info(f"Current keyset: {ledger.keyset.id}")
        await asyncio.sleep(n_seconds)


async def start_auth():
    await migrate_databases(auth_ledger.db, auth_migrations)
    logger.info("Starting auth ledger.")
    await auth_ledger.init_keysets()
    await auth_ledger.init_auth()
    logger.info("Auth ledger started.")


async def start_mint():
    await migrate_databases(ledger.db, mint_migrations)
    logger.info("Starting mint ledger.")
    await ledger.startup_ledger()
    logger.info("Mint started.")
    # asyncio.create_task(rotate_keys())


async def shutdown_mint():
    await ledger.shutdown_ledger()
    logger.info("Mint shutdown.")
    logger.remove()

rpc_server = None
async def start_management_rpc():
    global rpc_server
    rpc_server = await management_rpc.serve(copy(ledger))

async def shutdown_management_rpc():
    if rpc_server:
        await management_rpc.shutdown(rpc_server)
