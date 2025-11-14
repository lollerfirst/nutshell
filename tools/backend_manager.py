#!/usr/bin/env python
"""
Management tool for Cashu lightning backend plugins.

This script helps list available backends and verify their functionality.
"""

import asyncio
import argparse
import sys
from typing import List

from cashu.core.base import Unit
from cashu.lightning.plugins import (
    initialize_plugin_system,
    BackendRegistry,
    create_backend_instance
)


async def test_backend(backend_name: str, unit: str = "sat") -> bool:
    """
    Test a backend by creating an instance and checking its status.
    
    Args:
        backend_name: The name of the backend to test.
        unit: The unit to use for testing (default: sat).
        
    Returns:
        True if the backend was successfully tested, False otherwise.
    """
    try:
        unit_enum = Unit[unit]
    except KeyError:
        print(f"Error: Invalid unit '{unit}'. Valid units are: {', '.join([u.name for u in Unit])}")
        return False
    
    backend = create_backend_instance(backend_name, unit=unit_enum)
    if not backend:
        print(f"Error: Failed to create backend instance for '{backend_name}'")
        return False
    
    try:
        status = await backend.status()
        print(f"Backend '{backend_name}' status: Balance={status.balance.amount} {status.balance.unit.name}")
        print(f"  Supports MPP: {backend.supports_mpp}")
        print(f"  Supports descriptions: {backend.supports_description}")
        print(f"  Supports incoming payment stream: {backend.supports_incoming_payment_stream}")
        print(f"  Supported units: {', '.join([u.name for u in backend.supported_units])}")
        return True
    except Exception as e:
        print(f"Error testing backend '{backend_name}': {str(e)}")
        return False


def list_backends() -> None:
    """List all available backends."""
    backends = BackendRegistry.list_backends()
    
    if not backends:
        print("No backends registered.")
        return
    
    print(f"Found {len(backends)} registered backends:")
    for name, backend_class in backends.items():
        print(f"  - {name}")


async def main(args: argparse.Namespace) -> int:
    """Main entry point for the management tool."""
    plugin_dirs = args.plugin_dirs if args.plugin_dirs else []
    initialize_plugin_system(plugin_dirs)
    
    if args.list:
        list_backends()
        return 0
    
    if args.test:
        backends_to_test = [args.test]
        success = await test_backend(args.test, args.unit)
        return 0 if success else 1
    
    if args.test_all:
        backends = BackendRegistry.list_backends()
        success = True
        
        for name in backends:
            print(f"Testing backend '{name}'...")
            backend_success = await test_backend(name, args.unit)
            success = success and backend_success
            print()  # Add a blank line between backends
            
        return 0 if success else 1
    
    # If no action specified, show help
    parser.print_help()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cashu Lightning Backend Plugin Manager")
    
    parser.add_argument("--plugin-dirs", "-p", nargs="+", help="Additional plugin directories to search")
    parser.add_argument("--list", "-l", action="store_true", help="List all available backends")
    parser.add_argument("--test", "-t", metavar="BACKEND", help="Test a specific backend")
    parser.add_argument("--test-all", "-a", action="store_true", help="Test all available backends")
    parser.add_argument("--unit", "-u", default="sat", help="Unit to use for testing (default: sat)")
    
    args = parser.parse_args()
    
    sys.exit(asyncio.run(main(args)))
