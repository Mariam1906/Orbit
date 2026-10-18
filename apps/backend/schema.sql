-- Orbit MVP Database Schema

-- 1. Merchants Table
-- Stores the SaaS founders/businesses using Orbit
CREATE TABLE merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Plans Table
-- Stores the pricing tiers created by the merchant (e.g., "Pro Plan - 29 USDC/month")
CREATE TABLE plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    usdc_amount NUMERIC NOT NULL, -- Storing as numeric to handle large Stellar numbers without precision loss
    interval_seconds BIGINT NOT NULL, -- e.g., 2592000 for 30 days
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Subscriptions Table
-- Stores the customers who have subscribed to a specific plan
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id UUID NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    customer_wallet_address VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'cancelled', 'past_due'
    next_billing_date TIMESTAMP WITH TIME ZONE NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_dunning_retry_at TIMESTAMP WITH TIME ZONE,
    dunning_status VARCHAR(50) DEFAULT NULL, -- 'pending', 'in_progress', 'exhausted', 'recovered'
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure a customer can't accidentally subscribe to the exact same plan twice concurrently
    UNIQUE(plan_id, customer_wallet_address)
);

-- 4. Idempotency Keys Table
-- Stores the outcome of mutating requests sent with an Idempotency-Key header so
-- that client retries replay the original response instead of re-executing it.
-- Keys are scoped per merchant and expire after a TTL (24 hours by default).
-- merchant_id is NOT NULL because UNIQUE(merchant_id, key) treats NULLs as
-- distinct, which would silently disable deduplication.
CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL,
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    request_path VARCHAR(255) NOT NULL,
    request_hash VARCHAR(64) NOT NULL, -- SHA-256 hex of the canonicalized request body
    status VARCHAR(50) NOT NULL CHECK (status IN ('in_progress', 'completed', 'failed')),
    response_code INTEGER,
    response_body JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), -- last claim/finalize; used to detect abandoned in_progress claims
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    UNIQUE(merchant_id, key)
);

CREATE INDEX idempotency_keys_expires_at_idx ON idempotency_keys (expires_at);

-- 5. Billing Locks Table
-- Lease-based mutex that serializes billing operations (pull preparation and
-- submission) per subscription. A lease that is never released (e.g. the API
-- process crashed) becomes available again once locked_until passes.
CREATE TABLE billing_locks (
    subscription_id UUID PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    lock_token UUID NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6. API Keys Table
-- Merchant API credentials. Keys are formatted orb_<live|test>_<64 hex chars>; only
-- the SHA-256 hex digest of the full key is stored, the secret itself is shown to the
-- merchant once at creation. key_prefix (e.g. orb_live_71c2) identifies a key in the
-- dashboard without revealing it. A key is active while revoked_at IS NULL.
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    key_hash VARCHAR(64) NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    environment VARCHAR(20) NOT NULL CHECK (environment IN ('live', 'test')),
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- Authentication looks keys up by hash; hashes of random 256-bit secrets never collide
CREATE UNIQUE INDEX api_keys_key_hash_idx ON api_keys (key_hash);
CREATE INDEX api_keys_merchant_id_idx ON api_keys (merchant_id);

-- Multi-tenant organization boundary and wallet-bound role membership (#68).
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL UNIQUE REFERENCES merchants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(80) NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    wallet_address VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, wallet_address)
);
CREATE INDEX organization_members_org_role_idx ON organization_members (organization_id, role);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS organization_member_wallet VARCHAR(255);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

-- 7. Audit Logs Table
-- Immutable audit records for financial mutations and administrative actions
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
    actor_address VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    ip_address VARCHAR(100),
    changes_before JSONB,
    changes_after JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX audit_logs_merchant_id_idx ON audit_logs (merchant_id);
CREATE INDEX audit_logs_created_at_idx ON audit_logs (created_at DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action);

-- 8. Webhook Endpoints Table
-- Merchant configured destination URLs for event notifications
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    signing_secret VARCHAR(255) NOT NULL,
    events JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX webhooks_merchant_id_idx ON webhooks (merchant_id);

-- 9. Webhook Deliveries Table
-- Dispatched webhook events, HTTP response status codes, and attempt payloads
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    request_headers JSONB,
    response_status INTEGER,
    response_body TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(50) NOT NULL DEFAULT 'success', -- 'success', 'failed'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX webhook_deliveries_merchant_id_idx ON webhook_deliveries (merchant_id);
CREATE INDEX webhook_deliveries_webhook_id_idx ON webhook_deliveries (webhook_id);
CREATE INDEX webhook_deliveries_created_at_idx ON webhook_deliveries (created_at DESC);

-- 10. Reconciliation State Table
-- Progress markers for the ledger reconciliation worker (reconciliation.js). The
-- 'soroban_events' row stores the getEvents cursor so a restarted worker resumes
-- where it stopped instead of rescanning the RPC retention window.
-- Backend-only: RLS with no policies denies anon/authenticated access.
CREATE TABLE reconciliation_state (
    id VARCHAR(64) PRIMARY KEY,
    event_cursor TEXT,
    last_ledger BIGINT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
ALTER TABLE reconciliation_state ENABLE ROW LEVEL SECURITY;

-- Secret rotation retains the previous key until in-flight deliveries expire.
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS previous_signing_secret VARCHAR(255);
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS secret_rotated_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS tax_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    recipient_wallet VARCHAR(255) NOT NULL,
    amount NUMERIC NOT NULL,
    currency VARCHAR(32) NOT NULL,
    tax_type VARCHAR(32) NOT NULL DEFAULT '1099',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS tax_transactions_merchant_date_idx ON tax_transactions (merchant_id, created_at);

-- #76: immutable on-chain settlement ledger, keyed on transaction hash to
-- prevent duplicate export rows on idempotent retries. Amounts are raw USDC
-- token units and never reconstructed from mutable plan prices.
CREATE TABLE IF NOT EXISTS payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE RESTRICT,
    plan_id UUID NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    customer_wallet_address VARCHAR(255) NOT NULL,
    amount_usdc_units NUMERIC NOT NULL CHECK (amount_usdc_units >= 0),
    status VARCHAR(32) NOT NULL DEFAULT 'settled' CHECK (status IN ('settled')),
    tx_hash VARCHAR(128) NOT NULL UNIQUE,
    settled_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS payment_transactions_merchant_date_idx
    ON payment_transactions (merchant_id, settled_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS payment_transactions_merchant_plan_idx
    ON payment_transactions (merchant_id, plan_id, settled_at DESC);
ALTER TABLE payment_transactions ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS signing_sessions (
    id UUID PRIMARY KEY,
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    xdr TEXT NOT NULL,
    required_signers INTEGER NOT NULL CHECK (required_signers > 0),
    signatures JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS signing_sessions_merchant_status_idx ON signing_sessions (merchant_id, status);
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMP WITH TIME ZONE;

-- Fiat-denominated plans & exchange rate oracle cache (#96)
--
-- Plans are priced either directly in USDC (raw token units in usdc_amount)
-- or in a supported fiat currency (currency + price_amount). Fiat plans are
-- converted to raw USDC units at the moment of pull using the newest cached
-- oracle rate, guarded by the subscription's quoted_rate slippage limit.
ALTER TABLE plans ADD COLUMN IF NOT EXISTS currency VARCHAR(8) NOT NULL DEFAULT 'USDC'
    CHECK (currency IN ('USDC', 'USD', 'EUR'));
ALTER TABLE plans ADD COLUMN IF NOT EXISTS price_amount NUMERIC CHECK (price_amount > 0);

-- Fiat->USDC rate quoted when the subscription was created; the pull flow
-- rejects settlements whose live rate drifted more than 2% from this quote.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS quoted_rate NUMERIC;

-- Timestamped historical exchange rate cache written by the oracle worker.
-- One row per sync per pair; readers always take the newest row per base.
CREATE TABLE IF NOT EXISTS exchange_rates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_currency VARCHAR(8) NOT NULL,
    quote_currency VARCHAR(8) NOT NULL DEFAULT 'USDC',
    rate NUMERIC NOT NULL CHECK (rate > 0),
    source VARCHAR(32) NOT NULL,
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS exchange_rates_pair_fetched_at_idx
    ON exchange_rates (base_currency, quote_currency, fetched_at DESC);
-- Backend-only: service role bypasses RLS, no public policy is defined.
ALTER TABLE exchange_rates ENABLE ROW LEVEL SECURITY;

-- Atomically claims an idempotency key. Returns {"claimed": true, "record": ...}
-- when the caller now owns the key and must execute the request, or
-- {"claimed": false, "record": ...} with the existing record otherwise.
-- An existing record is taken over only when it has expired, or when it belongs to
-- the same request (path + body hash) and either failed or was abandoned
-- in_progress for longer than p_in_progress_timeout_seconds.
CREATE OR REPLACE FUNCTION claim_idempotency_key(
    p_merchant_id UUID,
    p_key VARCHAR,
    p_request_path VARCHAR,
    p_request_hash VARCHAR,
    p_ttl_seconds INTEGER,
    p_in_progress_timeout_seconds INTEGER
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_record idempotency_keys;
BEGIN
    INSERT INTO idempotency_keys (key, merchant_id, request_path, request_hash, status, expires_at)
    VALUES (p_key, p_merchant_id, p_request_path, p_request_hash, 'in_progress', NOW() + make_interval(secs => p_ttl_seconds))
    ON CONFLICT (merchant_id, key) DO UPDATE
        SET request_path = EXCLUDED.request_path,
            request_hash = EXCLUDED.request_hash,
            status = 'in_progress',
            response_code = NULL,
            response_body = NULL,
            created_at = CASE WHEN idempotency_keys.expires_at <= NOW() THEN NOW() ELSE idempotency_keys.created_at END,
            updated_at = NOW(),
            expires_at = EXCLUDED.expires_at
        WHERE idempotency_keys.expires_at <= NOW()
           OR (
                idempotency_keys.request_path = EXCLUDED.request_path
                AND idempotency_keys.request_hash = EXCLUDED.request_hash
                AND (
                    idempotency_keys.status = 'failed'
                    OR (
                        idempotency_keys.status = 'in_progress'
                        AND idempotency_keys.updated_at <= NOW() - make_interval(secs => p_in_progress_timeout_seconds)
                    )
                )
           )
    RETURNING * INTO v_record;

    IF FOUND THEN
        RETURN jsonb_build_object('claimed', true, 'record', to_jsonb(v_record));
    END IF;

    SELECT * INTO v_record
    FROM idempotency_keys
    WHERE merchant_id = p_merchant_id AND key = p_key;

    RETURN jsonb_build_object('claimed', false, 'record', to_jsonb(v_record));
END;
$$;

-- Acquires the billing lease for a subscription. Returns true when acquired,
-- false when another holder's lease is still live.
CREATE OR REPLACE FUNCTION acquire_billing_lock(
    p_subscription_id UUID,
    p_lock_token UUID,
    p_ttl_seconds INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO billing_locks (subscription_id, lock_token, locked_until)
    VALUES (p_subscription_id, p_lock_token, NOW() + make_interval(secs => p_ttl_seconds))
    ON CONFLICT (subscription_id) DO UPDATE
        SET lock_token = EXCLUDED.lock_token,
            locked_until = EXCLUDED.locked_until,
            created_at = NOW()
        WHERE billing_locks.locked_until <= NOW();

    RETURN FOUND;
END;
$$;

-- Releases the billing lease, but only if the caller still holds it.
CREATE OR REPLACE FUNCTION release_billing_lock(
    p_subscription_id UUID,
    p_lock_token UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM billing_locks
    WHERE subscription_id = p_subscription_id AND lock_token = p_lock_token;

    RETURN FOUND;
END;
$$;

-- Housekeeping: delete expired idempotency keys and stale billing leases.
-- Schedule with pg_cron, e.g. SELECT cron.schedule('purge-idempotency', '0 * * * *', 'SELECT purge_expired_idempotency_keys()');
CREATE OR REPLACE FUNCTION purge_expired_idempotency_keys() RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM idempotency_keys WHERE expires_at <= NOW();
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    DELETE FROM billing_locks WHERE locked_until <= NOW();
    RETURN v_deleted;
END;
$$;

-- These functions are backend-only: Postgres grants EXECUTE to PUBLIC by default
-- and Supabase additionally grants it to anon/authenticated.
REVOKE EXECUTE ON FUNCTION claim_idempotency_key(UUID, VARCHAR, VARCHAR, VARCHAR, INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION acquire_billing_lock(UUID, UUID, INTEGER) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION release_billing_lock(UUID, UUID) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION purge_expired_idempotency_keys() FROM PUBLIC, anon, authenticated;

-- 11. Relayer Fee Usage Table
-- Daily network fees (in stroops) the Orbit relayer has sponsored per merchant, used to
-- enforce RELAYER_DAILY_FEE_LIMIT_STROOPS. Days are UTC. fee_stroops holds the fee
-- reserved before submission, corrected to the fee actually charged once confirmed.
CREATE TABLE relayer_fee_usage (
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    usage_date DATE NOT NULL,
    fee_stroops BIGINT NOT NULL DEFAULT 0 CHECK (fee_stroops >= 0),
    tx_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    PRIMARY KEY (merchant_id, usage_date)
);

-- Atomically books p_amount against today's budget. Returns the usage date it was booked
-- against, or NULL when it would take the merchant over p_daily_limit.
CREATE OR REPLACE FUNCTION reserve_relayer_fee(
    p_merchant_id UUID,
    p_amount BIGINT,
    p_daily_limit BIGINT
) RETURNS DATE
LANGUAGE plpgsql
AS $$
DECLARE
    v_usage_date DATE := (NOW() AT TIME ZONE 'UTC')::DATE;
BEGIN
    IF p_amount > p_daily_limit THEN
        RETURN NULL;
    END IF;

    INSERT INTO relayer_fee_usage (merchant_id, usage_date, fee_stroops)
    VALUES (p_merchant_id, v_usage_date, p_amount)
    ON CONFLICT (merchant_id, usage_date) DO UPDATE
        SET fee_stroops = relayer_fee_usage.fee_stroops + EXCLUDED.fee_stroops,
            updated_at = NOW()
        WHERE relayer_fee_usage.fee_stroops + EXCLUDED.fee_stroops <= p_daily_limit;

    IF FOUND THEN
        RETURN v_usage_date;
    END IF;
    RETURN NULL;
END;
$$;

-- Corrects a booking: refunds an unsubmitted reservation or settles it to the charged fee.
CREATE OR REPLACE FUNCTION adjust_relayer_fee(
    p_merchant_id UUID,
    p_usage_date DATE,
    p_fee_delta BIGINT,
    p_tx_delta INTEGER
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE relayer_fee_usage
    SET fee_stroops = GREATEST(0, fee_stroops + p_fee_delta),
        tx_count = tx_count + p_tx_delta,
        updated_at = NOW()
    WHERE merchant_id = p_merchant_id AND usage_date = p_usage_date;
END;
$$;

REVOKE EXECUTE ON FUNCTION reserve_relayer_fee(UUID, BIGINT, BIGINT) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION adjust_relayer_fee(UUID, DATE, BIGINT, INTEGER) FROM PUBLIC, anon, authenticated;

-- Backend-only: RLS with no policies denies anon/authenticated access.
ALTER TABLE relayer_fee_usage ENABLE ROW LEVEL SECURITY;

-- ==============================================================================
-- Row Level Security (RLS) Configuration
-- ==============================================================================
--
-- Security Model:
-- 1. The backend Express API connects using SUPABASE_SERVICE_ROLE_KEY, which
--    inherently bypasses RLS in PostgreSQL / Supabase.
-- 2. Direct client access using the public anon key is strictly read-only and
--    limited to what the public checkout flow requires (reading plans and
--    associated merchant names and wallet addresses).
-- 3. All table mutations (INSERT, UPDATE, DELETE) across all tables are forbidden
--    to anon/public clients and must be executed through the backend.
-- 4. The subscriptions table has NO public policies defined, enforcing default-deny
--    for the anon key (preventing any direct listing or modification of subscriber data).

ALTER TABLE merchants ENABLE ROW LEVEL SECURITY;
ALTER TABLE plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

-- Public checkout read access for plans and merchant public identifiers
CREATE POLICY "Allow public read access to merchants for checkout"
    ON merchants FOR SELECT
    USING (true);

CREATE POLICY "Allow public read access to plans for checkout"
    ON plans FOR SELECT
    USING (true);

-- No public policies for subscriptions, idempotency_keys, billing_locks, api_keys, audit_logs, webhooks, or webhook_deliveries:
-- default-deny prevents anon key access.
-- No open INSERT or UPDATE policies: all mutations require backend service role.

-- Issue #74: backend-only customer portal wallet sign-in and session revocation.
-- Execute with a DB migration tool in environments with existing deployments.
CREATE TABLE IF NOT EXISTS customer_portal_challenges (
    id UUID PRIMARY KEY,
    wallet_address VARCHAR(56) NOT NULL,
    message TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS portal_challenges_expiry_idx
    ON customer_portal_challenges (expires_at);
CREATE TABLE IF NOT EXISTS customer_portal_sessions (
    id UUID PRIMARY KEY,
    wallet_address VARCHAR(56) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS portal_sessions_wallet_idx
    ON customer_portal_sessions (wallet_address, expires_at);

-- A receipt is only formed from a confirmed pull.execute audit event.
-- The wallet predicate is applied in the view before pagination by backend queries.
-- Do not claim an exact amount: old audit entries do not contain a verified amount.
CREATE OR REPLACE VIEW customer_portal_receipts WITH (security_invoker = true) AS
SELECT a.id, s.id AS subscription_id, s.customer_wallet_address,
       p.name AS plan_name, m.name AS merchant_name,
       a.created_at, a.changes_after->>'txHash' AS tx_hash
FROM audit_logs AS a
JOIN subscriptions AS s ON a.resource_id = s.id::text
JOIN plans AS p ON s.plan_id = p.id
JOIN merchants AS m ON p.merchant_id = m.id
WHERE a.action = 'pull.execute'
  AND a.changes_after->>'txHash' IS NOT NULL;

ALTER TABLE customer_portal_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_portal_sessions ENABLE ROW LEVEL SECURITY;
-- Backend service-role only: the view must never bypass subscription RLS
-- for anon users or leak transaction history through a public endpoint.
REVOKE ALL ON TABLE customer_portal_challenges FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE customer_portal_sessions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE customer_portal_receipts FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON customer_portal_challenges TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON customer_portal_sessions TO service_role;
GRANT SELECT ON customer_portal_receipts TO service_role;
-- Optional housekeeping job: periodically DELETE expired rows.


-- Issue #75: append after existing schema.sql (fiat plan columns are already defined).
-- Application coupon values are in the plan's denomination:
-- USDC plans use raw 7-decimal token units; USD/EUR plans use major fiat units.
CREATE TABLE IF NOT EXISTS coupons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    code VARCHAR(32) NOT NULL CHECK (code ~ '^[A-Z0-9_-]{3,32}$'),
    discount_type VARCHAR(16) NOT NULL CHECK (discount_type IN ('percent', 'amount')),
    discount_value NUMERIC NOT NULL CHECK (discount_value > 0),
    duration_months INTEGER NOT NULL DEFAULT 1 CHECK (duration_months BETWEEN 1 AND 120),
    max_redemptions INTEGER CHECK (max_redemptions IS NULL OR max_redemptions > 0),
    redemptions_count INTEGER NOT NULL DEFAULT 0 CHECK (redemptions_count >= 0),
    expires_at TIMESTAMP WITH TIME ZONE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT coupons_percent_cap CHECK (discount_type <> 'percent' OR discount_value <= 99),
    CONSTRAINT coupons_limit_floor CHECK (max_redemptions IS NULL OR max_redemptions >= redemptions_count)
);
CREATE UNIQUE INDEX IF NOT EXISTS coupons_merchant_code_idx ON coupons (merchant_id, code);
CREATE INDEX IF NOT EXISTS coupons_expiry_idx ON coupons (expires_at);
ALTER TABLE coupons ENABLE ROW LEVEL SECURITY;
-- No public RLS policies: merchant access is enforced through backend API keys.

ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS coupon_id UUID REFERENCES coupons(id) ON DELETE SET NULL;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_original_amount NUMERIC;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_discounted_amount NUMERIC;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_currency VARCHAR(8);
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_duration_months INTEGER;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS promotion_onchain_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Atomic redemption: coupon is locked for the full transaction, and insertion
-- and redemption-count increment roll back together on duplicate subscription.
-- Call through the backend using the Supabase service role only.
CREATE OR REPLACE FUNCTION redeem_coupon_subscription(
    p_plan_id UUID,
    p_customer_wallet_address VARCHAR,
    p_metadata JSONB,
    p_code VARCHAR,
    p_quoted_rate NUMERIC DEFAULT NULL
) RETURNS subscriptions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    v_plan plans%ROWTYPE;
    v_coupon coupons%ROWTYPE;
    v_original NUMERIC;
    v_discounted NUMERIC;
    v_currency VARCHAR(8);
    v_sub subscriptions%ROWTYPE;
BEGIN
    SELECT * INTO v_plan FROM plans WHERE id = p_plan_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Plan not found' USING ERRCODE = 'P7503';
    END IF;
    -- Concurrent redemptions serialize on the coupon row.
    SELECT * INTO v_coupon FROM coupons
      WHERE merchant_id = v_plan.merchant_id AND code = UPPER(TRIM(p_code))
      FOR UPDATE;
    IF NOT FOUND OR NOT v_coupon.active OR
       (v_coupon.expires_at IS NOT NULL AND v_coupon.expires_at <= NOW()) THEN
        RAISE EXCEPTION 'Coupon invalid or expired' USING ERRCODE = 'P7501';
    END IF;
    IF v_coupon.max_redemptions IS NOT NULL AND
       v_coupon.redemptions_count >= v_coupon.max_redemptions THEN
        RAISE EXCEPTION 'Coupon redemption limit reached' USING ERRCODE = 'P7502';
    END IF;
    v_currency := COALESCE(v_plan.currency, 'USDC');
    IF v_currency = 'USDC' THEN
        v_original := v_plan.usdc_amount;
    ELSIF v_currency IN ('USD', 'EUR') THEN
        v_original := v_plan.price_amount;
    ELSE
        RAISE EXCEPTION 'Unsupported plan currency' USING ERRCODE = 'P7501';
    END IF;
    IF v_original IS NULL OR v_original <= 0 THEN
        RAISE EXCEPTION 'Invalid plan price' USING ERRCODE = 'P7501';
    END IF;
    v_discounted := CASE WHEN v_coupon.discount_type = 'percent' THEN
        v_original * (100 - v_coupon.discount_value) / 100
      ELSE v_original - v_coupon.discount_value END;
    v_discounted := TRUNC(v_discounted, CASE WHEN v_currency = 'USDC' THEN 0 ELSE 2 END);
    IF v_discounted <= 0 OR v_discounted >= v_original THEN
        RAISE EXCEPTION 'Discount is not valid for this plan price' USING ERRCODE = 'P7501';
    END IF;
    -- No on-chain authorization has been verified at checkout yet. The legacy
    -- contract uses a fixed vault amount, so never label a coupon checkout as
    -- an activated discounted subscription without confirming compatible terms.
    INSERT INTO subscriptions (
        plan_id, customer_wallet_address, metadata, next_billing_date, status,
        quoted_rate, coupon_id, promotion_original_amount, promotion_discounted_amount,
        promotion_currency, promotion_duration_months, promotion_expires_at,
        promotion_onchain_verified
    ) VALUES (
        p_plan_id, p_customer_wallet_address, COALESCE(p_metadata, '{}'::jsonb), NOW(), 'pending_promo',
        p_quoted_rate, v_coupon.id, v_original, v_discounted,
        v_currency, v_coupon.duration_months, NOW() + make_interval(months => v_coupon.duration_months),
        FALSE
    ) RETURNING * INTO v_sub;
    UPDATE coupons SET redemptions_count = redemptions_count + 1 WHERE id = v_coupon.id;
    RETURN v_sub;
END;
$$;
REVOKE ALL ON FUNCTION redeem_coupon_subscription(UUID, VARCHAR, JSONB, VARCHAR, NUMERIC)
    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION redeem_coupon_subscription(UUID, VARCHAR, JSONB, VARCHAR, NUMERIC)
    TO service_role;

-- 101-ledger-checkpoints.sql
-- Apply once to existing Supabase projects before enabling the indexer.
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
    stream_id TEXT PRIMARY KEY,
    last_processed_ledger_sequence BIGINT NOT NULL CHECK (last_processed_ledger_sequence >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS contract_events (
    stream_id TEXT NOT NULL REFERENCES ledger_checkpoints(stream_id),
    id TEXT NOT NULL,
    ledger_sequence BIGINT NOT NULL,
    transaction_hash TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    merchant_address TEXT,
    topics JSONB NOT NULL,
    value JSONB NOT NULL,
    closed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (stream_id, id)
);
CREATE INDEX IF NOT EXISTS contract_events_merchant_ledger_idx ON contract_events (merchant_address, ledger_sequence);
ALTER TABLE ledger_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_events ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION commit_ledger_batch(
    p_stream_id TEXT, p_expected_sequence BIGINT, p_last_sequence BIGINT, p_events JSONB
) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_saved BIGINT;
BEGIN
    IF p_expected_sequence < 0 OR p_last_sequence <= p_expected_sequence THEN
        RAISE EXCEPTION 'Invalid checkpoint range';
    END IF;
    INSERT INTO ledger_checkpoints (stream_id, last_processed_ledger_sequence)
        VALUES (p_stream_id, p_expected_sequence) ON CONFLICT DO NOTHING;
    SELECT last_processed_ledger_sequence INTO v_saved FROM ledger_checkpoints
        WHERE stream_id = p_stream_id FOR UPDATE;
    IF v_saved <> p_expected_sequence THEN
        RAISE EXCEPTION 'Checkpoint changed; reload before retrying';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_events) e
        WHERE (e->>'ledger_sequence')::BIGINT <= p_expected_sequence
           OR (e->>'ledger_sequence')::BIGINT > p_last_sequence) THEN
        RAISE EXCEPTION 'Event outside checkpoint range';
    END IF;
    INSERT INTO contract_events (stream_id, id, ledger_sequence, transaction_hash,
        contract_id, event_name, merchant_address, topics, value, closed_at)
    SELECT p_stream_id, e.id, e.ledger_sequence, e.transaction_hash, e.contract_id,
        e.event_name, e.merchant_address, e.topics, e.value, e.closed_at
    FROM jsonb_to_recordset(p_events) AS e(id TEXT, ledger_sequence BIGINT,
        transaction_hash TEXT, contract_id TEXT, event_name TEXT, merchant_address TEXT,
        topics JSONB, value JSONB, closed_at TIMESTAMPTZ)
    ON CONFLICT (stream_id, id) DO NOTHING;
    UPDATE ledger_checkpoints SET last_processed_ledger_sequence = p_last_sequence,
        updated_at = NOW() WHERE stream_id = p_stream_id;
END;
$$;
REVOKE EXECUTE ON FUNCTION commit_ledger_batch(TEXT, BIGINT, BIGINT, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION commit_ledger_batch(TEXT, BIGINT, BIGINT, JSONB) TO service_role;

-- 102-merchant-analytics.sql
-- Batches nested payment pages in one query. Payment amounts are raw USDC units.
CREATE OR REPLACE FUNCTION graphql_subscription_payments(p_merchant_id UUID, p_requests JSONB)
RETURNS TABLE(request_index INTEGER, payment JSONB) LANGUAGE sql STABLE AS $$
    SELECT (r.ordinality - 1)::INTEGER, to_jsonb(a)
    FROM jsonb_array_elements(p_requests) WITH ORDINALITY r(request, ordinality)
    CROSS JOIN LATERAL (
        SELECT * FROM audit_logs a WHERE a.merchant_id = p_merchant_id
          AND a.action = 'pull.execute' AND a.resource_type = 'subscription'
          AND a.resource_id = r.request->>'id'
        ORDER BY a.created_at DESC, a.id
        LIMIT LEAST(GREATEST((r.request->>'limit')::INTEGER, 1), 100)
        OFFSET LEAST(GREATEST((r.request->>'offset')::INTEGER, 0), 100000)
    ) a;
$$;

CREATE OR REPLACE FUNCTION merchant_analytics(p_merchant_id UUID, p_from TIMESTAMPTZ, p_to TIMESTAMPTZ)
RETURNS JSONB LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'activeSubscribers', (SELECT COUNT(*) FROM subscriptions s JOIN plans p ON p.id = s.plan_id
            WHERE p.merchant_id = p_merchant_id AND s.status = 'active'),
        'settledPayments', COUNT(*),
        'settledAmount', COALESCE(SUM((changes_after->>'amount')::NUMERIC), 0)::TEXT
    ) FROM audit_logs WHERE merchant_id = p_merchant_id AND action = 'pull.execute'
        AND created_at >= p_from AND created_at < p_to;
$$;
REVOKE EXECUTE ON FUNCTION graphql_subscription_payments(UUID, JSONB) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION merchant_analytics(UUID, TIMESTAMPTZ, TIMESTAMPTZ) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION graphql_subscription_payments(UUID, JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION merchant_analytics(UUID, TIMESTAMPTZ, TIMESTAMPTZ) TO service_role;

-- 105-billing-resolution.sql
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_failure JSONB;

-- The audit record and billing-date advancement either both commit or both roll back.
CREATE OR REPLACE FUNCTION waive_subscription_interval(p_subscription_id UUID, p_merchant_id UUID, p_actor_address TEXT)
RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE v_sub subscriptions; v_interval BIGINT; v_before JSONB;
BEGIN
    SELECT s.* INTO v_sub FROM subscriptions s JOIN plans p ON p.id = s.plan_id
        WHERE s.id = p_subscription_id AND p.merchant_id = p_merchant_id FOR UPDATE OF s;
    IF NOT FOUND OR v_sub.status <> 'past_due' THEN RETURN NULL; END IF;
    IF v_sub.last_failure->>'code' = 'rpc_timeout' AND v_sub.last_failure->>'transaction_hash' IS NOT NULL THEN RETURN NULL; END IF;
    SELECT interval_seconds INTO v_interval FROM plans WHERE id = v_sub.plan_id;
    v_before := to_jsonb(v_sub);
    UPDATE subscriptions SET status = 'active', retry_count = 0,
        dunning_status = NULL, next_dunning_retry_at = NULL, last_failure = NULL,
        next_billing_date = GREATEST(next_billing_date, NOW()) + make_interval(secs => v_interval::DOUBLE PRECISION)
        WHERE id = p_subscription_id RETURNING * INTO v_sub;
    INSERT INTO audit_logs (merchant_id, actor_address, action, resource_type, resource_id, changes_before, changes_after)
        VALUES (p_merchant_id, p_actor_address, 'subscription.interval_waived', 'subscription',
            p_subscription_id::TEXT, v_before, to_jsonb(v_sub));
    RETURN to_jsonb(v_sub);
END;
$$;
REVOKE EXECUTE ON FUNCTION waive_subscription_interval(UUID, UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION waive_subscription_interval(UUID, UUID, TEXT) TO service_role;

-- Reconcile an RPC timeout exactly once, using only the hash previously stored
-- by the backend. The HTTP route verifies its outcome with Soroban RPC first.
CREATE OR REPLACE FUNCTION resolve_pending_pull(p_subscription_id UUID, p_merchant_id UUID,
    p_transaction_hash TEXT, p_succeeded BOOLEAN, p_settled_at TIMESTAMPTZ)
RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE v_sub subscriptions; v_plan plans; v_before JSONB;
BEGIN
    SELECT s.* INTO v_sub FROM subscriptions s JOIN plans p ON p.id = s.plan_id
        WHERE s.id = p_subscription_id AND p.merchant_id = p_merchant_id FOR UPDATE OF s;
    IF NOT FOUND OR v_sub.last_failure->>'code' IS DISTINCT FROM 'rpc_timeout'
        OR v_sub.last_failure->>'transaction_hash' IS DISTINCT FROM p_transaction_hash THEN RETURN NULL; END IF;
    v_before := to_jsonb(v_sub);
    SELECT * INTO v_plan FROM plans WHERE id = v_sub.plan_id;
    IF p_succeeded THEN
        UPDATE subscriptions SET status = 'active', retry_count = 0, dunning_status = NULL,
            next_dunning_retry_at = NULL, last_failure = NULL,
            next_billing_date = p_settled_at + make_interval(secs => v_plan.interval_seconds::DOUBLE PRECISION)
            WHERE id = p_subscription_id RETURNING * INTO v_sub;
        INSERT INTO audit_logs (merchant_id, actor_address, action, resource_type, resource_id, changes_before, changes_after)
            VALUES (p_merchant_id, NULL, 'pull.execute', 'subscription', p_subscription_id::TEXT,
                v_before, jsonb_build_object('txHash', p_transaction_hash, 'amount', v_plan.usdc_amount::TEXT,
                    'status', v_sub.status, 'next_billing_date', v_sub.next_billing_date));
    ELSE
        UPDATE subscriptions SET last_failure = jsonb_build_object('code', 'unknown',
            'message', 'The previously pending transaction failed on-chain. A fresh retry can now be prepared.',
            'transaction_hash', p_transaction_hash, 'occurred_at', NOW())
            WHERE id = p_subscription_id RETURNING * INTO v_sub;
    END IF;
    RETURN to_jsonb(v_sub);
END;
$$;
REVOKE EXECUTE ON FUNCTION resolve_pending_pull(UUID, UUID, TEXT, BOOLEAN, TIMESTAMPTZ) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION resolve_pending_pull(UUID, UUID, TEXT, BOOLEAN, TIMESTAMPTZ) TO service_role;

-- #143: Custom branded Soroban contract deployment per merchant
ALTER TABLE merchants ADD COLUMN IF NOT EXISTS contract_id VARCHAR(255);

-- #138: GDPR/CCPA Cryptographic Data Shredding & Privacy Compliance
CREATE TABLE IF NOT EXISTS user_encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    subject_hash VARCHAR(64) NOT NULL,
    encrypted_dek TEXT,
    iv VARCHAR(64),
    auth_tag VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- 'active', 'shredded'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    shredded_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(merchant_id, subject_hash)
);
CREATE INDEX IF NOT EXISTS user_encryption_keys_merchant_subject_idx ON user_encryption_keys (merchant_id, subject_hash);
ALTER TABLE user_encryption_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS compliance_deletion_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    subject_hash VARCHAR(64) NOT NULL,
    certificate_data JSONB NOT NULL,
    signature VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS compliance_deletion_certificates_merchant_subject_idx ON compliance_deletion_certificates (merchant_id, subject_hash);
ALTER TABLE compliance_deletion_certificates ENABLE ROW LEVEL SECURITY;
-- 160-payout-splits.sql
-- Automated merchant payout split engine (#160). Each settlement is split
-- between partner treasury wallets; payout_distributions links the primary pull
-- transaction hash to every secondary forward transfer hash.
CREATE TABLE IF NOT EXISTS merchant_payout_splits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    recipient_wallet VARCHAR(255) NOT NULL,
    percentage_basis_points INTEGER NOT NULL
        CHECK (percentage_basis_points > 0 AND percentage_basis_points <= 10000),
    label VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (merchant_id, recipient_wallet)
);
CREATE INDEX IF NOT EXISTS merchant_payout_splits_merchant_active_idx
    ON merchant_payout_splits (merchant_id, is_active);

CREATE TABLE IF NOT EXISTS payout_distributions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
    primary_tx_hash VARCHAR(128) NOT NULL,
    recipient_wallet VARCHAR(255) NOT NULL,
    split_id UUID REFERENCES merchant_payout_splits(id) ON DELETE SET NULL,
    label VARCHAR(255),
    percentage_basis_points INTEGER NOT NULL
        CHECK (percentage_basis_points > 0 AND percentage_basis_points <= 10000),
    amount_usdc_units NUMERIC NOT NULL CHECK (amount_usdc_units >= 0),
    status VARCHAR(32) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'submitted', 'settled', 'failed')),
    split_tx_hash VARCHAR(128),
    error TEXT,
    settled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (primary_tx_hash, recipient_wallet)
);
CREATE INDEX IF NOT EXISTS payout_distributions_merchant_created_idx
    ON payout_distributions (merchant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payout_distributions_status_idx
    ON payout_distributions (status);
CREATE INDEX IF NOT EXISTS payout_distributions_primary_tx_idx
    ON payout_distributions (primary_tx_hash);

ALTER TABLE merchant_payout_splits ENABLE ROW LEVEL SECURITY;
ALTER TABLE payout_distributions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE merchant_payout_splits FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE payout_distributions FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON merchant_payout_splits TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON payout_distributions TO service_role;

-- 164-plan-price-indexation.sql
-- Scheduled plan price indexation (#164): upcoming price changes, advance
-- notices, and one-click subscriber re-authorization tokens.
CREATE TABLE IF NOT EXISTS plan_price_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id UUID NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    new_usdc_amount NUMERIC NOT NULL CHECK (new_usdc_amount > 0),
    new_price_amount NUMERIC CHECK (new_price_amount IS NULL OR new_price_amount > 0),
    status VARCHAR(32) NOT NULL DEFAULT 'scheduled'
        CHECK (status IN ('scheduled', 'notified', 'applied', 'cancelled')),
    advance_notice_days INTEGER NOT NULL DEFAULT 30
        CHECK (advance_notice_days >= 0 AND advance_notice_days <= 365),
    notified_at TIMESTAMP WITH TIME ZONE,
    applied_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (plan_id, effective_date)
);
CREATE INDEX IF NOT EXISTS plan_price_schedules_status_date_idx
    ON plan_price_schedules (status, effective_date);
CREATE INDEX IF NOT EXISTS plan_price_schedules_plan_idx
    ON plan_price_schedules (plan_id, effective_date DESC);

CREATE TABLE IF NOT EXISTS plan_price_reauthorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id UUID NOT NULL REFERENCES plan_price_schedules(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    token VARCHAR(128) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'authorized', 'expired')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    authorized_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (schedule_id, subscription_id)
);
CREATE INDEX IF NOT EXISTS plan_price_reauthorizations_token_idx
    ON plan_price_reauthorizations (token);
CREATE INDEX IF NOT EXISTS plan_price_reauthorizations_schedule_idx
    ON plan_price_reauthorizations (schedule_id, status);

ALTER TABLE plan_price_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE plan_price_reauthorizations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE plan_price_schedules FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE plan_price_reauthorizations FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON plan_price_schedules TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON plan_price_reauthorizations TO service_role;

-- 185-contract-state-snapshots.sql
-- Automated smart contract state snapshot backup and disaster recovery sync (#185).
CREATE TABLE IF NOT EXISTS contract_state_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id VARCHAR(128) NOT NULL UNIQUE,
    contract_id VARCHAR(128) NOT NULL,
    ledger_sequence BIGINT NOT NULL CHECK (ledger_sequence >= 0),
    schema_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    checksum_sha256 VARCHAR(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
    vault_count INTEGER NOT NULL DEFAULT 0 CHECK (vault_count >= 0),
    plan_count INTEGER NOT NULL DEFAULT 0 CHECK (plan_count >= 0),
    config_count INTEGER NOT NULL DEFAULT 0 CHECK (config_count >= 0),
    storage_location TEXT,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    snapshot_payload JSONB,
    captured_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    restored_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS contract_state_snapshots_contract_ledger_idx
    ON contract_state_snapshots (contract_id, ledger_sequence DESC);
CREATE INDEX IF NOT EXISTS contract_state_snapshots_captured_at_idx
    ON contract_state_snapshots (captured_at DESC);

ALTER TABLE contract_state_snapshots ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE contract_state_snapshots FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON contract_state_snapshots TO service_role;

-- 11. Webhook Incident Alert Channels (#189)
-- Per-merchant destinations for endpoint incident and recovery alerts.
-- config holds { webhook_url } for slack, { routing_key } for pagerduty, { email } for email.
CREATE TABLE IF NOT EXISTS webhook_alert_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL CHECK (type IN ('slack', 'pagerduty', 'email')),
    config JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS webhook_alert_channels_merchant_id_idx ON webhook_alert_channels (merchant_id);

-- Cross-asset checkout (#191): router a merchant has approved on-chain for swap subscriptions.
-- The checkout widget reads this to route swap subscriptions through an approved router.
ALTER TABLE plans ADD COLUMN IF NOT EXISTS swap_router_address VARCHAR(56);

-- 12. Dunning Workflows (#190)
-- A merchant's retry cadence and per-step email templates. Without a row the
-- default Day 1 / 3 / 5 / 7 schedule applies.
CREATE TABLE IF NOT EXISTS dunning_workflows (
    merchant_id UUID PRIMARY KEY REFERENCES merchants(id) ON DELETE CASCADE,
    steps JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
