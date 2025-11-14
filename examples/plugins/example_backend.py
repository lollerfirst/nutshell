"""
Example plugin demonstrating a custom Cashu Lightning backend.
"""
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


@register_backend("ExampleCustomBackend")
class ExampleCustomBackend(LightningBackend):
    """
    Example custom Lightning backend implementation.
    
    This is a very simple demonstration backend that doesn't actually
    connect to a real Lightning service.
    """
    
    supported_units = {Unit.sat}
    supports_description = True
    
    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        """Initialize the example backend."""
        self.assert_unit_supported(unit)
        self.unit = unit
        self._balance = 10000  # Initial balance of 10,000 sats
        self.paid_invoices = []
        self.payment_queue = asyncio.Queue(0)
        
    async def status(self) -> StatusResponse:
        """Get the current status of the backend."""
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
        """Create a new Lightning invoice."""
        self.assert_unit_supported(amount.unit)
        
        # Create a fake invoice
        invoice_id = hashlib.sha256(f"{amount.amount}:{memo}".encode()).hexdigest()
        payment_request = f"example_backend_invoice_{amount.amount}_{invoice_id}"
        
        return InvoiceResponse(
            ok=True,
            checking_id=invoice_id,
            payment_request=payment_request,
            error_message=None
        )
    
    async def pay_invoice(self, quote: MeltQuote, fee_limit_msat: int) -> PaymentResponse:
        """Pay a Lightning invoice."""
        # Simulate payment by reducing balance
        if quote.amount.amount > self._balance:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="Insufficient balance"
            )
        
        # Extract invoice ID from our custom format
        invoice_parts = quote.request.split("_")
        if len(invoice_parts) < 3 or invoice_parts[0] != "example":
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="Invalid invoice format"
            )
        
        amount = int(invoice_parts[2])
        invoice_id = invoice_parts[3] if len(invoice_parts) > 3 else "unknown"
        
        # Deduct the amount from balance
        self._balance -= amount
        
        # Add to paid invoices and notify listeners
        self.paid_invoices.append(invoice_id)
        await self.payment_queue.put(invoice_id)
        
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=invoice_id,
            fee=Amount(unit=self.unit, amount=0),  # No fee
            preimage=hashlib.sha256(invoice_id.encode()).hexdigest()
        )
    
    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        """Check the status of an invoice."""
        # Always return settled in this example
        return PaymentStatus(
            result=PaymentResult.SETTLED
        )
    
    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """Check the status of a payment."""
        if checking_id in self.paid_invoices:
            return PaymentStatus(
                result=PaymentResult.SETTLED,
                fee=Amount(unit=self.unit, amount=0)
            )
        return PaymentStatus(
            result=PaymentResult.UNKNOWN,
            error_message="Payment not found"
        )
        
    async def get_payment_quote(self, melt_quote: PostMeltQuoteRequest) -> PaymentQuoteResponse:
        """Get a quote for a payment."""
        # Parse our custom invoice format
        if not melt_quote.request.startswith("example_"):
            raise ValueError("Invalid invoice format")
            
        try:
            # Format: example_backend_invoice_AMOUNT_ID
            parts = melt_quote.request.split("_")
            amount = int(parts[2]) if len(parts) > 2 else 0
            checking_id = parts[3] if len(parts) > 3 else "unknown"
            
            return PaymentQuoteResponse(
                checking_id=checking_id,
                amount=Amount(unit=self.unit, amount=amount),
                fee=Amount(unit=self.unit, amount=0)  # No fee in this example
            )
        except (IndexError, ValueError):
            raise ValueError("Failed to parse example invoice")
    
    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        """Stream of paid invoices."""
        while True:
            invoice_id = await self.payment_queue.get()
            yield invoice_id


# Function to register backends with the registry
def register_backends(registry):
    """Register backends with the provided registry."""
    registry.register("ExampleCustomBackend", ExampleCustomBackend)
