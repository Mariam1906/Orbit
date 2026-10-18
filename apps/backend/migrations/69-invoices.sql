-- Verifiable receipts generated for each settled payment (#69).
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    payment_transaction_id UUID NOT NULL UNIQUE REFERENCES payment_transactions(id) ON DELETE RESTRICT,
    subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE RESTRICT,
    invoice_number VARCHAR(32) NOT NULL UNIQUE,
    status VARCHAR(16) NOT NULL DEFAULT 'processing' CHECK (status IN ('processing', 'ready', 'failed')),
    transaction_hash VARCHAR(128) NOT NULL,
    ledger_sequence BIGINT,
    settled_at TIMESTAMP WITH TIME ZONE NOT NULL,
    storage_bucket VARCHAR(128),
    storage_path TEXT,
    failure_reason TEXT,
    generated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS invoices_merchant_settled_idx ON invoices (merchant_id, settled_at DESC);
CREATE INDEX IF NOT EXISTS invoices_subscription_settled_idx ON invoices (subscription_id, settled_at DESC);
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE invoices FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON invoices TO service_role;
