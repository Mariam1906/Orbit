import { describe, expect, it, vi } from 'vitest';
import { createInvoiceService, explorerUrl, formatUsdc, generateReceiptPdf } from '../invoices.js';

const payment = {
  id: '3b40c934-0c2b-4b12-8b68-72e9f9c4a044', merchant_id: 'merchant-1', subscription_id: 'sub-1',
  amount_usdc_units: '290000000', tx_hash: 'abc123', settled_at: '2026-10-18T00:00:00.000Z',
};

describe('verifiable invoice receipts', () => {
  it('formats raw USDC units without losing precision', () => {
    expect(formatUsdc('290000000')).toBe('29 USDC');
    expect(formatUsdc('123456789')).toBe('12.3456789 USDC');
    expect(explorerUrl('abc123')).toContain('/testnet/tx/abc123');
  });

  it('renders a real PDF receipt with the settlement verification QR code', async () => {
    const pdf = await generateReceiptPdf({
      invoiceNumber: 'ORB-ABC123', merchantName: 'Acme', customerWallet: 'GUSER', planName: 'Pro',
      amountUsdcUnits: '290000000', settledAt: payment.settled_at, txHash: payment.tx_hash, ledgerSequence: 123,
    });
    expect(pdf.subarray(0, 4).toString()).toBe('%PDF');
    expect(pdf.length).toBeGreaterThan(1000);
  });

  it('stores a generated receipt privately and marks the invoice ready', async () => {
    const ready = { id: 'invoice-1', status: 'ready', storage_path: 'merchant-1/invoice-1.pdf' };
    const query = {
      insert: vi.fn().mockReturnThis(), select: vi.fn().mockReturnThis(), single: vi.fn()
        .mockResolvedValueOnce({ data: { id: 'invoice-1', invoice_number: 'ORB-TEST' }, error: null })
        .mockResolvedValueOnce({ data: ready, error: null }),
      update: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
    };
    const upload = vi.fn().mockResolvedValue({ error: null });
    const supabase = { from: vi.fn(() => query), storage: { from: vi.fn(() => ({ upload })) } };
    const service = createInvoiceService({ supabase });
    const result = await service.createForSettledPayment({ payment, merchant: { name: 'Acme' }, plan: { name: 'Pro' }, subscription: { customer_wallet_address: 'GUSER' } });
    expect(result.invoice.status).toBe('ready');
    expect(upload).toHaveBeenCalledWith('merchant-1/invoice-1.pdf', expect.any(Buffer), expect.objectContaining({ contentType: 'application/pdf' }));
  });
});
