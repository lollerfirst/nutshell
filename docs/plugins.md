# Cashu Lightning Backend Plugin System

## Overview

The Cashu Lightning backend plugin system allows developers to create custom Lightning backend implementations without modifying the core Cashu codebase. This enables easier integration of different Lightning implementations and payment systems.

## Creating a Custom Backend

To create a custom backend, you need to create a Python module that:

1. Imports the required Cashu classes
2. Creates a new class that inherits from `LightningBackend`
3. Implements all the required abstract methods
4. Registers the backend with the plugin system

Here's a template to get you started:

```python
from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.lightning.base import (
    LightningBackend,
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)
from cashu.lightning.plugins import register_backend

@register_backend("MyCustomBackend")
class MyCustomBackend(LightningBackend):
    """
    My custom Lightning backend implementation.
    """
    
    # Specify which units this backend supports
    supported_units = {Unit.sat}
    
    # Does this backend support invoice descriptions?
    supports_description = True
    
    # Does this backend support Multi-Path Payments?
    supports_mpp = False
    
    # Does this backend support streaming of incoming payments?
    supports_incoming_payment_stream = False
    
    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        """Initialize the backend."""
        self.assert_unit_supported(unit)
        self.unit = unit
        # Add your initialization code here
        
    async def status(self) -> StatusResponse:
        """Get the current status of the backend."""
        # Implement status check
        pass
    
    async def create_invoice(
        self, 
        amount: Amount, 
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None
    ) -> InvoiceResponse:
        """Create a new Lightning invoice."""
        # Implement invoice creation
        pass
    
    async def pay_invoice(self, quote: MeltQuote, fee_limit_msat: int) -> PaymentResponse:
        """Pay a Lightning invoice."""
        # Implement invoice payment
        pass
    
    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        """Check the status of an invoice."""
        # Implement invoice status check
        pass
    
    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """Check the status of a payment."""
        # Implement payment status check
        pass
        
    async def get_payment_quote(self, melt_quote: PostMeltQuoteRequest) -> PaymentQuoteResponse:
        """Get a quote for a payment."""
        # Implement payment quote
        pass
    
    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        """Stream of paid invoices."""
        # Implement paid invoices stream
        pass

# Alternatively, you can register the backend directly:
# from cashu.lightning.plugins import BackendRegistry
# BackendRegistry.register("MyCustomBackend", MyCustomBackend)
```

## Installing a Plugin

There are two ways to install a backend plugin:

### 1. Plugin Directory

Place your plugin module in one of the plugin directories:

- The default plugin directory is: `~/.cashu/plugins/`
- You can configure additional plugin directories using the `MINT_PLUGIN_DIRS` environment variable or in your `.env` file:
  ```
  MINT_PLUGIN_DIRS=["path/to/plugins", "/another/path/to/plugins"]
  ```

### 2. Direct Import

If you're building a custom application using Cashu, you can register your backend directly in your code:

```python
from cashu.lightning.plugins import BackendRegistry
from mymodule import MyCustomBackend

# Register your backend
BackendRegistry.register("MyCustomBackend", MyCustomBackend)

# Now you can use it in settings:
# MINT_BACKEND_BOLT11_SAT="MyCustomBackend"
```

## Using a Custom Backend

After registering your backend, configure Cashu to use it by setting the appropriate environment variables:

```
MINT_BACKEND_BOLT11_SAT="MyCustomBackend"
```

You can specify different backends for different units:

```
MINT_BACKEND_BOLT11_SAT="MyCustomBackend"
MINT_BACKEND_BOLT11_USD="AnotherBackend"
MINT_BACKEND_BOLT11_EUR="ThirdBackend"
```

## Example: A Simple Plugin

Here's a minimal example of a backend plugin that just logs operations without actually connecting to any Lightning Network:

```python
import hashlib
import asyncio
from typing import AsyncGenerator, Optional

from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.lightning.base import (
    LightningBackend,
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)
from cashu.lightning.plugins import register_backend

@register_backend("LoggingBackend")
class LoggingBackend(LightningBackend):
    """
    A simple backend that just logs operations without actual functionality.
    """
    
    supported_units = {Unit.sat}
    supports_description = True
    
    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self._balance = 10000  # Fixed balance for demonstration
        self._paid_queue = asyncio.Queue(0)
        print(f"LoggingBackend initialized with unit {unit}")
        
    async def status(self) -> StatusResponse:
        print("LoggingBackend: status check")
        return StatusResponse(
            balance=Amount(unit=self.unit, amount=self._balance),
            error_message=None
        )
    
    async def create_invoice(
        self, 
        amount: Amount, 
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None
    ) -> InvoiceResponse:
        print(f"LoggingBackend: create invoice for {amount.amount} {amount.unit}")
        invoice_id = hashlib.sha256(f"{amount.amount}:{memo}".encode()).hexdigest()
        payment_request = f"logging_invoice_{amount.amount}_{invoice_id}"
        
        return InvoiceResponse(
            ok=True,
            checking_id=invoice_id,
            payment_request=payment_request,
            error_message=None
        )
    
    async def pay_invoice(self, quote: MeltQuote, fee_limit_msat: int) -> PaymentResponse:
        print(f"LoggingBackend: pay invoice {quote.request}")
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id="test",
            fee=Amount(unit=self.unit, amount=0),
            preimage="0" * 64
        )
    
    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        print(f"LoggingBackend: check invoice status {checking_id}")
        return PaymentStatus(result=PaymentResult.SETTLED)
    
    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        print(f"LoggingBackend: check payment status {checking_id}")
        return PaymentStatus(result=PaymentResult.SETTLED)
        
    async def get_payment_quote(self, melt_quote: PostMeltQuoteRequest) -> PaymentQuoteResponse:
        print(f"LoggingBackend: get payment quote {melt_quote.request}")
        return PaymentQuoteResponse(
            checking_id="test",
            amount=Amount(unit=self.unit, amount=100),
            fee=Amount(unit=self.unit, amount=1)
        )
    
    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        print("LoggingBackend: starting paid invoices stream")
        while True:
            invoice_id = await self._paid_queue.get()
            yield invoice_id

# Register with plugin system
def register_backends(registry):
    """Register backends with the registry."""
    registry.register("LoggingBackend", LoggingBackend)
```

Save this file as `logging_backend.py` in your plugin directory (`~/.cashu/plugins/`).

## Testing Your Plugin

To test if your plugin is loaded correctly:

1. Start Cashu with the plugin directory configured
2. Configure Cashu to use your backend:
   ```
   MINT_BACKEND_BOLT11_SAT="MyCustomBackend"
   ```
3. Check the logs for any errors during startup

If your backend is loaded correctly, Cashu will use it for the specified unit.

## Debugging Tips

- Enable debug logs to see more information about plugin loading:
  ```
  LOG_LEVEL=DEBUG
  ```
- Check if your plugin appears in the registered backends:
  ```python
  from cashu.lightning.plugins import BackendRegistry
  print(BackendRegistry.list_backends())
  ```
- Make sure your plugin file is properly formatted as a Python module
