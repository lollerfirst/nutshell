"""
Plugin system for Cashu Lightning backends.

This module provides a registry and loading mechanism for Lightning backend plugins,
allowing developers to create and register custom backends without modifying the core code.
"""

import importlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from loguru import logger

from ..core.base import Unit
from .base import LightningBackend


class BackendRegistry:
    """Registry for Lightning backend plugins."""
    
    _backends: Dict[str, Type[LightningBackend]] = {}
    _plugin_dirs: List[str] = []
    
    @classmethod
    def register(cls, name: str, backend_class: Type[LightningBackend]) -> None:
        """
        Register a backend class with a name.
        
        Args:
            name: The name to register the backend under.
            backend_class: The backend class to register.
        """
        if name in cls._backends:
            logger.warning(f"Overriding existing backend: {name}")
        
        cls._backends[name] = backend_class
        logger.debug(f"Registered backend: {name}")
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[LightningBackend]]:
        """
        Get a backend class by name.
        
        Args:
            name: The name of the backend.
            
        Returns:
            The backend class, or None if not found.
        """
        return cls._backends.get(name)
    
    @classmethod
    def list_backends(cls) -> Dict[str, Type[LightningBackend]]:
        """
        List all registered backends.
        
        Returns:
            A dictionary of backend names to backend classes.
        """
        return cls._backends.copy()
    
    @classmethod
    def add_plugin_dir(cls, plugin_dir: str) -> None:
        """
        Add a directory to search for plugins.
        
        Args:
            plugin_dir: The directory path to search for plugins.
        """
        if not os.path.isdir(plugin_dir):
            logger.warning(f"Plugin directory does not exist: {plugin_dir}")
            return
        
        if plugin_dir not in cls._plugin_dirs:
            cls._plugin_dirs.append(plugin_dir)
            logger.debug(f"Added plugin directory: {plugin_dir}")
    
    @classmethod
    def load_plugins(cls) -> None:
        """
        Load all plugins from the registered plugin directories.
        """
        # First, register all built-in backends
        cls._register_builtin_backends()
        
        # Then load external plugins
        for plugin_dir in cls._plugin_dirs:
            cls._load_from_directory(plugin_dir)
    
    @classmethod
    def _register_builtin_backends(cls) -> None:
        """Register all built-in backends."""
        # Import all built-in backends to trigger their registration
        from . import blink, clnrest, corelightningrest, fake, lnbits, strike
        from .lnd_grpc import lnd_grpc
        from . import lndrest
        
        # Register built-in backends
        cls.register("FakeWallet", fake.FakeWallet)
        cls.register("LNbitsWallet", lnbits.LNbitsWallet)
        cls.register("LndRestWallet", lndrest.LndRestWallet)
        cls.register("LndRPCWallet", lnd_grpc.LndRPCWallet)
        cls.register("StrikeWallet", strike.StrikeWallet)
        cls.register("BlinkWallet", blink.BlinkWallet)
        cls.register("CLNRestWallet", clnrest.CLNRestWallet)
        cls.register("CoreLightningRestWallet", corelightningrest.CoreLightningRestWallet)
    
    @classmethod
    def _load_from_directory(cls, plugin_dir: str) -> None:
        """
        Load plugins from a directory.
        
        Args:
            plugin_dir: The directory to load plugins from.
        """
        plugin_path = Path(plugin_dir)
        
        if not plugin_path.exists() or not plugin_path.is_dir():
            logger.warning(f"Plugin directory does not exist: {plugin_dir}")
            return
        
        # Look for Python files that might contain plugins
        for py_file in plugin_path.glob("**/*.py"):
            module_name = f"cashu_plugin_{py_file.stem}"
            
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    logger.debug(f"Loaded plugin module: {module_name} from {py_file}")
                    
                    # Plugin modules must define a register function that will be called
                    if hasattr(module, "register_backends"):
                        module.register_backends(cls)
                        logger.info(f"Registered backends from plugin: {module_name}")
            
            except Exception as e:
                logger.error(f"Failed to load plugin {py_file}: {e}")


# Add decorator for easy backend registration
def register_backend(name: str):
    """
    Decorator to register a backend class with the registry.
    
    Args:
        name: The name to register the backend under.
        
    Returns:
        A decorator function.
    """
    def decorator(backend_class: Type[LightningBackend]) -> Type[LightningBackend]:
        BackendRegistry.register(name, backend_class)
        return backend_class
    
    return decorator


def get_backend_class(name: str) -> Optional[Type[LightningBackend]]:
    """
    Get a backend class by name.
    
    Args:
        name: The name of the backend.
        
    Returns:
        The backend class, or None if not found.
    """
    return BackendRegistry.get(name)


def create_backend_instance(name: str, unit: Unit, **kwargs) -> Optional[LightningBackend]:
    """
    Create an instance of a backend by name.
    
    Args:
        name: The name of the backend.
        unit: The unit to use for the backend.
        **kwargs: Additional arguments to pass to the backend constructor.
        
    Returns:
        An instance of the backend, or None if the backend was not found.
    """
    backend_class = BackendRegistry.get(name)
    if backend_class:
        return backend_class(unit=unit, **kwargs)
    return None


# Initialize the registry
def initialize_plugin_system(additional_plugin_dirs: List[str] = None) -> None:
    """
    Initialize the plugin system by loading all plugins.
    
    Args:
        additional_plugin_dirs: Additional directories to search for plugins.
    """
    # Add default plugin directory (user's home directory)
    default_plugin_dir = os.path.join(str(Path.home()), ".cashu", "plugins")
    BackendRegistry.add_plugin_dir(default_plugin_dir)
    
    # Add additional plugin directories
    if additional_plugin_dirs:
        for plugin_dir in additional_plugin_dirs:
            BackendRegistry.add_plugin_dir(plugin_dir)
    
    # Load all plugins
    BackendRegistry.load_plugins()
