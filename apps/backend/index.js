const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const { z } = require('zod');
const { StrKey, Keypair, rpc, Networks, TransactionBuilder, Contract, Address } = require('@stellar/stellar-sdk');
const { executeIdempotently, withBillingLock, sendResult } = require('./idempotency');
const { API_KEY_ENVIRONMENTS, issueApiKey, requireApiKey } = require('./apiKeys');
const { createRateLimiter, createStoreFromEnv } = require('./rateLimit');
const { createReputationScorer, createHorizonWalletLookup } = require('./reputation');
const { isRelayerError, createRelayerFromEnv } = require('./relayer');
const { getAuditLogsQuerySchema, getClientIp, getActorAddress, writeAuditLog } = require('./audit');
const {
    createWebhookSchema,
    updateWebhookSchema,
    backfillWebhookSchema,
    generateSigningSecret,
    dispatchWebhookEvent,
    resendWebhookDelivery,
    replayWebhookEvents,
    setDeliveryObserver,
} = require('./webhooks');
const { createDeliveryAlertObserver, registerWebhookAlertRoutes } = require('./webhook-alerts');
const {
    DUNNING_INTERVAL_DAYS,
    MAX_DUNNING_RETRIES,
    calculateNextDunningRetry,
    generateRecoveryLink,
    markSubscriptionPastDue,
    processDunningRetries,
} = require('./dunning');
const { registerComplianceRoutes } = require('./compliance');
const { registerDunningWorkflowRoutes, loadDunningWorkflow } = require('./dunning-workflow');
const { registerSigningSessionRoutes } = require('./signing-sessions');
const { registerTransactionExportRoute, confirmedSettlementAmount } = require('./transaction-report');
const { registerCustomerPortalRoutes } = require('./customer-portal');
const { registerFailureRecoveryRoutes } = require('./failure-recovery');
const { registerAnalyticsRoutes } = require('./analytics');
const { registerCouponRoutes, normalizeCode } = require('./coupons');
const { registerGraphql } = require('./graphql');
const { configuredIndexer, registerIndexerRoutes } = require('./ledger-indexer');
const { recordPullFailure, registerBillingResolutionRoutes } = require('./billing-resolution');
const {
    isFiatCurrency,
    getRate,
    calculateUsdcUnits,
    quoteUsdcAmount,
    getSupportedRates,
    startOracleWorker,
    SlippageError,
    RateUnavailableError,
} = require('./oracle');
const {
    createPayoutSplitDispatcher,
    createStellarSplitForwarder,
    registerPayoutSplitRoutes,
} = require('./payout-splits');
const {
    createPriceIndexationWorker,
    registerPriceIndexationRoutes,
} = require('./price-indexation');
const {
    createSnapshotExportWorker,
    registerSnapshotRoutes,
} = require('./contract-state-snapshot');
const { getDatabaseManager } = require('./db');
const { registerPrivacyRoutes } = require('./privacy');
const { registerProofRoutes } = require('./proofs');
const { registerRpcProxyRoute } = require('./rpc-proxy');

const app = express();
// Set when running behind a reverse proxy so req.ip (used for rate limiting) is the client's address
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);
app.use(cors());

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000;
// Shared by every limiter and the reputation scorer: Redis (with an in-memory
// fallback) when REDIS_URL is set, so limits hold across all API instances
const rateLimitStore = createStoreFromEnv();
// Wallet age is scored only when Horizon is configured; tests inject app.locals.walletLookup
const horizonWalletLookup = process.env.HORIZON_URL
    ? createHorizonWalletLookup({ horizonUrl: process.env.HORIZON_URL })
    : null;
const reputation = createReputationScorer({
    store: rateLimitStore,
    walletLookup: async (address) => {
        const lookup = app.locals.walletLookup || horizonWalletLookup;
        return lookup ? lookup(address) : null;
    },
    ipTrustAfterMs: Number(process.env.REPUTATION_IP_TRUST_AFTER_MS) || undefined,
});
// Coarse per-IP limit on every route, public or not, so unauthenticated traffic
// (including floods of invalid API keys) cannot exhaust the database. Scaled by the
// IP's reputation: new IPs and repeat offenders get less, merchant IPs more.
const ipRateLimit = createRateLimiter({
    name: 'ip',
    store: rateLimitStore,
    windowMs: RATE_LIMIT_WINDOW_MS,
    limit: reputation.ipLimit(Number(process.env.IP_RATE_LIMIT_MAX) || 300),
    keyGenerator: (req) => req.ip,
    onLimitReached: (req) => reputation.recordViolation(req.ip),
});
// Per-API-key limit on authenticated merchant routes, scaled by key tier and wallet age
const apiKeyRateLimit = createRateLimiter({
    name: 'key',
    store: rateLimitStore,
    windowMs: RATE_LIMIT_WINDOW_MS,
    limit: reputation.apiKeyLimit(Number(process.env.API_KEY_RATE_LIMIT_MAX) || 100),
    keyGenerator: (req) => req.apiKey?.id,
    message: "API key rate limit exceeded, please retry later",
});
app.locals.rateLimiters = { ip: ipRateLimit, apiKey: apiKeyRateLimit };
app.locals.reputation = reputation;

app.use(ipRateLimit);
app.use(express.json());

// Multi-region database manager with read-replica failover (#139)
const dbManager = getDatabaseManager();
const getPrimarySupabase = (appInstance = app) => dbManager.getPrimaryClient(appInstance);
const getReadSupabase = (appInstance = app) => dbManager.getReadClient(appInstance);
const getSupabase = () => getPrimarySupabase(app);

// Merchant routes: authenticate the API key, then apply its rate limit
const authenticateMerchant = [requireApiKey(getSupabase), apiKeyRateLimit];
registerAnalyticsRoutes(app, getSupabase);

// Allows tests to inject a mock Soroban RPC server instead of hitting testnet
const getSorobanServer = (rpcUrl) => app.locals.sorobanServer || new rpc.Server(rpcUrl);

// One relayer per process: its sequence cache and channel pool must be shared by all requests.
// Tests inject their own through app.locals.relayer.
let defaultRelayer;
const getRelayer = () => {
    if (app.locals.relayer) return app.locals.relayer;
    if (defaultRelayer === undefined) {
        defaultRelayer = createRelayerFromEnv({
            server: getSorobanServer(process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org'),
            getSupabase,
        });
    }
    return defaultRelayer;
};

// Forward transfers for merchant payout splits (#160). The merchant treasury (or a
// dedicated split relayer) signs and pays; when no key is configured, splits are
// still recorded as pending so an operator can reconcile them later.
let defaultSplitForwarder;
const getSplitForwarder = () => {
    if (app.locals.splitForwarder !== undefined) return app.locals.splitForwarder;
    if (defaultSplitForwarder === undefined) {
        const secret = process.env.SPLIT_RELAYER_SECRET_KEY || process.env.RELAYER_SECRET_KEY;
        const tokenContractId = process.env.SPLIT_TOKEN_CONTRACT_ID || process.env.USDC_CONTRACT_ID;
        if (!secret || !tokenContractId) {
            defaultSplitForwarder = null;
        } else {
            defaultSplitForwarder = createStellarSplitForwarder({
                server: getSorobanServer(process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org'),
                sourceKeypair: Keypair.fromSecret(secret),
                tokenContractId,
                networkPassphrase: process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET,
            });
        }
    }
    return defaultSplitForwarder;
};

const getPayoutSplitDispatcher = () => createPayoutSplitDispatcher({
    supabase: getSupabase(),
    forwarder: getSplitForwarder(),
    getTreasuryWallet: async (merchantId) => {
        const supabase = getSupabase();
        if (!supabase) return null;
        const { data } = await supabase.from('merchants').select('wallet_address').eq('id', merchantId).maybeSingle();
        return data?.wallet_address ?? null;
    },
});

// Per-merchant throttle on relay requests, on top of the general API key limit
const relayRateLimit = createRateLimiter({
    name: 'relay',
    store: rateLimitStore,
    windowMs: Number(process.env.RELAYER_RATE_LIMIT_WINDOW_MS) || 60 * 1000,
    limit: Number(process.env.RELAYER_RATE_LIMIT_MAX) || 10,
    keyGenerator: (req) => req.merchant?.id,
    message: "Relay rate limit exceeded, please retry later",
});
app.locals.rateLimiters.relay = relayRateLimit;

// How long to keep polling getTransaction() for a submitted hash before giving up
const TX_POLL_TIMEOUT_MS = Number(process.env.TX_POLL_TIMEOUT_MS) || 30000;
const TX_POLL_INTERVAL_MS = Number(process.env.TX_POLL_INTERVAL_MS) || 1000;

// Billing lease for preparing a pull (simulation only)
const PREPARE_LOCK_TTL_SECONDS = Number(process.env.PREPARE_LOCK_TTL_SECONDS) || 60;
// Billing lease for submitting a pull must outlive confirmation polling
const submitLockTtlSeconds = (pollTimeoutMs) => Math.ceil(pollTimeoutMs / 1000) + 60;
// A relayed pull may also wait for a free channel and retry submission before polling
const relayLockTtlSeconds = (pollTimeoutMs) =>
    submitLockTtlSeconds(pollTimeoutMs) + Math.ceil((Number(process.env.RELAYER_QUEUE_TIMEOUT_MS) || 30000) / 1000) + 30;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Polls getTransaction(hash) until it settles to SUCCESS/FAILED, or returns NOT_FOUND on timeout
const waitForTransaction = async (server, hash, { timeoutMs = TX_POLL_TIMEOUT_MS, intervalMs = TX_POLL_INTERVAL_MS } = {}) => {
    const deadline = Date.now() + timeoutMs;
    let lastResponse = await server.getTransaction(hash);

    while (lastResponse.status === "NOT_FOUND" && Date.now() < deadline) {
        await sleep(intervalMs);
        lastResponse = await server.getTransaction(hash);
    }

    return lastResponse;
};

// ==========================================
// VALIDATION SCHEMAS
// ==========================================

const stellarAddressSchema = z.string().refine(
    (val) => StrKey.isValidEd25519PublicKey(val),
    { message: "must be a valid Stellar Ed25519 public address" }
);

// merchant_id is taken from the API key; a client-supplied value is only checked against it
const optionalMerchantIdSchema = z.string().uuid("merchant_id must be a valid UUID").optional();

// USDC plans store raw token units (USDC has 7 decimals, so 290000000 = 29
// USDC), same as the contract's amount_per_interval. Fiat plans (USD/EUR) store
// a price_amount in that currency, which the exchange rate oracle converts to
// raw USDC units at the moment of pull (#96).
const usdcPlanSchema = z.object({
    merchant_id: optionalMerchantIdSchema,
    name: z.string().trim().min(1, "name cannot be empty"),
    usdc_amount: z.coerce.number()
        .int("usdc_amount must be an integer in raw token units")
        .positive("usdc_amount must be greater than 0"),
    interval_seconds: z.coerce.number().int().positive("interval_seconds must be a positive integer"),
    currency: z.enum(['USDC']).default('USDC'),
});

const fiatPlanSchema = z.object({
    merchant_id: optionalMerchantIdSchema,
    name: z.string().trim().min(1, "name cannot be empty"),
    price_amount: z.coerce.number()
        .positive("price_amount must be greater than 0"),
    interval_seconds: z.coerce.number().int().positive("interval_seconds must be a positive integer"),
    currency: z.enum(['USD', 'EUR']),
});

// Validates the body against the schema for its pricing currency, so a USDC
// plan still requires usdc_amount and a fiat plan still requires price_amount.
const parseCreatePlanBody = (body) => {
    const currencyResult = z
        .object({ currency: z.enum(['USDC', 'USD', 'EUR']) })
        .safeParse({ currency: body?.currency ?? 'USDC' });
    if (!currencyResult.success) return currencyResult;

    return currencyResult.data.currency === 'USDC'
        ? usdcPlanSchema.safeParse(body)
        : fiatPlanSchema.safeParse(body);
};

const getPlanParamsSchema = z.object({
    id: z.string().uuid("id parameter must be a valid UUID"),
});

const getSubscribersQuerySchema = z.object({
    merchant_id: optionalMerchantIdSchema,
});

const createSubscriptionSchema = z.object({
    plan_id: z.string().uuid("plan_id must be a valid UUID"),
    customer_wallet_address: stellarAddressSchema,
    metadata: z.record(z.any()).optional().default({}),
    coupon_code: z.string().trim().min(3).max(32).regex(/^[A-Za-z0-9_-]+$/).optional(),
});

const triggerPullSchema = z.object({
    subscription_id: z.string().uuid("subscription_id must be a valid UUID"),
}).strict();

const submitPullSchema = z.object({
    subscription_id: z.string().uuid("subscription_id must be a valid UUID"),
    signed_xdr: z.string().min(1, "signed_xdr is required"),
}).strict();

const relaySubmitPullSchema = z.object({
    subscription_id: z.string().uuid("subscription_id must be a valid UUID"),
    signed_auth_entry_xdr: z.string().min(1, "signed_auth_entry_xdr is required"),
}).strict();

const createApiKeySchema = z.object({
    name: z.string().trim().min(1, "name cannot be empty").max(255, "name must be at most 255 characters"),
    environment: z.enum(API_KEY_ENVIRONMENTS, { message: "environment must be 'live' or 'test'" }),
}).strict();

const apiKeyParamsSchema = z.object({
    id: z.string().uuid("id parameter must be a valid UUID"),
});

// PostgREST reports a .single() lookup that matched no rows as an error, not as empty data
const isNoRowsError = (error) => error?.code === 'PGRST116';

// Postgres foreign key violation, e.g. inserting a subscription for a plan that does not exist
const isForeignKeyError = (error) => error?.code === '23503';

// Postgres unique violation, e.g. the same wallet subscribing to the same plan twice
const isUniqueViolation = (error) => error?.code === '23505';

const formatZodError = (err) => {
    const issue = err.issues[0];
    const field = issue.path.join('.') || 'input';
    return `Invalid input on ${field}: ${issue.message}`;
};

// Rejects a client-supplied merchant_id that names a merchant other than the authenticated one
const merchantMismatch = (req, merchantId) =>
    merchantId !== undefined && merchantId !== req.merchant.id;

const MERCHANT_MISMATCH_ERROR = { error: "merchant_id does not match the authenticated API key" };

// ==========================================
// ROUTE 1: POST /plans (Create a new pricing plan)
// ==========================================
app.post('/plans', authenticateMerchant, async (req, res) => {
    const parseResult = parseCreatePlanBody(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }
    if (merchantMismatch(req, parseResult.data.merchant_id)) return res.status(403).json(MERCHANT_MISMATCH_ERROR);

    const { name, currency, interval_seconds } = parseResult.data;
    const merchant_id = req.merchant.id;
    const supabase = getPrimarySupabase();
    if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
    if (!dbManager.isPrimaryHealthy()) {
        return res.status(503).json({ error: "Primary database is currently unavailable; write operations are suspended" });
    }

    const result = await executeIdempotently({
        supabase,
        req,
        label: "creating plan",
        resolveMerchant: () => ({ merchantId: merchant_id }),
    }, async () => {
        // Fiat plans: cache the current USDC equivalent for dashboards. The
        // authoritative amount is always recalculated at the moment of pull;
        // when the cache is cold the placeholder stays 0 until the oracle
        // worker publishes the first rate.
        let usdc_amount = parseResult.data.usdc_amount;
        const price_amount = parseResult.data.price_amount;
        if (isFiatCurrency(currency)) {
            usdc_amount = 0;
            try {
                const rateInfo = await getRate({
                    supabase,
                    fetchImpl: app.locals.fetchImpl,
                    currency,
                    allowNetwork: false,
                });
                if (rateInfo) usdc_amount = calculateUsdcUnits({ amount: price_amount, rate: rateInfo.rate });
            } catch (err) {
                console.error("Error deriving plan usdc_amount from oracle cache:", err.message);
            }
        }

        const { data, error } = await supabase
            .from('plans')
            .insert([{ merchant_id, name, currency, usdc_amount, price_amount, interval_seconds }])
            .select()
            .single();

        if (isForeignKeyError(error)) return { status: 404, body: { error: "Merchant not found" } };
        if (error) throw error;

        await writeAuditLog(supabase, {
            merchantId: merchant_id,
            actorAddress: getActorAddress(req, null),
            action: 'plan.create',
            resourceType: 'plan',
            resourceId: data.id,
            ipAddress: getClientIp(req),
            changesBefore: null,
            changesAfter: data,
        });

        return { status: 201, body: { message: "Plan created successfully", plan: data } };
    });
    sendResult(res, result);
});

// ==========================================
// ROUTE 2: GET /plans/:id (Fetch plan details for Checkout Widget)
// ==========================================
app.get('/plans/:id', async (req, res) => {
    const parseResult = getPlanParamsSchema.safeParse(req.params);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const { id } = parseResult.data;
        const supabase = getReadSupabase();
        if (!supabase) return res.status(500).json({ error: "Database client not initialized" });

        const { data, error } = await supabase
            .from('plans')
            .select('*, merchants(name, wallet_address)') // Also fetch the merchant's details
            .eq('id', id)
            .single();

        if (isNoRowsError(error)) return res.status(404).json({ error: "Plan not found" });
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "Plan not found" });

        res.status(200).json({ plan: data });
    } catch (err) {
        console.error("Error fetching plan:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 3: GET /subscribers (Fetch active subscribers for dashboard)
// ==========================================
app.get('/subscribers', authenticateMerchant, async (req, res) => {
    const parseResult = getSubscribersQuerySchema.safeParse(req.query);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }
    if (merchantMismatch(req, parseResult.data.merchant_id)) return res.status(403).json(MERCHANT_MISMATCH_ERROR);

    try {
        const merchant_id = req.merchant.id;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        // Find all subscriptions tied to plans owned by this merchant
        const { data, error } = await supabase
            .from('subscriptions')
            .select(`
                *,
                plans!inner(merchant_id, name, usdc_amount)
            `)
            .eq('plans.merchant_id', merchant_id);

        if (error) throw error;

        res.status(200).json({ subscribers: data });
    } catch (err) {
        console.error("Error fetching subscribers:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE: GET /rates (Exchange rate oracle)
// ==========================================
// Returns the supported fiat->USDC conversion pairs with their newest cached
// rate, refreshed from the live feed on a cold cache (#96).
app.get('/rates', async (req, res) => {
    try {
        const supabase = getReadSupabase();
        if (!supabase) return res.status(500).json({ error: "Database client not initialized" });

        const rates = await getSupportedRates({ supabase, fetchImpl: app.locals.fetchImpl });
        res.status(200).json(rates);
    } catch (err) {
        console.error("Error fetching exchange rates:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 4: POST /trigger-pull (The Blockchain Bridge)
// ==========================================
// Loads a subscription owned by the authenticated merchant. Another merchant's
// subscription is reported as not found so its existence is not revealed.
const loadPullContext = async (supabase, subscriptionId, merchant) => {
    const { data: sub, error: subError } = await supabase
        .from('subscriptions')
        .select(`
            *,
            plans ( merchant_id, usdc_amount, interval_seconds, currency, price_amount )
        `)
        .eq('id', subscriptionId)
        .single();

    if (isNoRowsError(subError) || !sub) return { status: 404, error: "Subscription not found" };
    if (subError) throw subError;
    if (sub.plans?.merchant_id !== merchant.id) return { status: 404, error: "Subscription not found" };
    // A coupon quote must not silently charge the fixed-price legacy Soroban vault.
    if (sub.coupon_id && !sub.promotion_onchain_verified) {
        return { status: 409, error: "Promotional vault terms are not verified on-chain; billing is blocked" };
    }

    return { sub, merchant };
};

// Records the confirmed outcome of a pull transaction, whoever submitted it
const applyPullOutcome = async ({
    supabase,
    req,
    sub,
    merchant,
    subscription_id,
    txHash,
    status,
    confirmation = null,
    server = null,
    signedTx = null,
    extraBody = {},
}) => {
    if (status === "SUCCESS") {
        const pullTime = new Date();
        const nextBilling = new Date(pullTime.getTime() + Number(sub.plans.interval_seconds) * 1000);

        await supabase
            .from('subscriptions')
            .update({
                next_billing_date: nextBilling.toISOString(),
                status: 'active',
                retry_count: 0,
                dunning_status: null,
                next_dunning_retry_at: null,
                last_failure: null,
            })
            .eq('id', subscription_id);

        await writeAuditLog(supabase, {
            merchantId: sub.plans.merchant_id,
            actorAddress: getActorAddress(req, merchant.wallet_address),
            action: 'pull.execute',
            resourceType: 'subscription',
            resourceId: subscription_id,
            ipAddress: getClientIp(req),
            changesBefore: { next_billing_date: sub.next_billing_date, status: sub.status },
            changesAfter: {
                next_billing_date: nextBilling.toISOString(),
                status: 'active',
                txHash,
                amount: String(sub.plans.usdc_amount),
            },
        });

        if (sub.plans.merchant_id) {
            // Fiat plans report the settled amount in raw USDC units
            // converted at the current cached rate (#96)
            let settledAmount = sub.plans.usdc_amount;
            if (isFiatCurrency(sub.plans?.currency)) {
                try {
                    const quote = await quoteUsdcAmount({
                        supabase,
                        plan: sub.plans,
                        subscription: sub,
                        fetchImpl: app.locals.fetchImpl,
                        allowNetwork: false,
                        enforceSlippage: false,
                    });
                    settledAmount = quote.usdc_amount;
                } catch {
                    // Keep the stored plan amount when the cache cannot price it
                }
            }

            // Only record amounts independently verified from the
            // successful on-chain funds_pulled event. Plan and oracle
            // quotes are not necessarily the vault's actual transfer.
            const verifiedAmount = confirmedSettlementAmount(
                confirmation,
                { customerWallet: sub.customer_wallet_address,
                  merchantWallet: merchant.wallet_address,
                  contractId: process.env.ORBIT_CONTRACT_ID },
            );
            if (verifiedAmount === null) {
                console.error('CRITICAL: confirmed transfer missing verified amount; reconcile transaction:', txHash);
            } else {
                const { error: paymentError } = await supabase.from('payment_transactions').insert([{
                    merchant_id: sub.plans.merchant_id,
                    subscription_id,
                    plan_id: sub.plan_id,
                    customer_wallet_address: sub.customer_wallet_address,
                    amount_usdc_units: verifiedAmount,
                    status: 'settled',
                    tx_hash: txHash,
                    settled_at: pullTime.toISOString(),
                }]);
                if (paymentError && paymentError.code !== '23505') {
                    console.error('CRITICAL: on-chain settlement needs ledger reconciliation:', txHash, paymentError);
                }
            }

            await dispatchWebhookEvent(supabase, {
                merchantId: sub.plans.merchant_id,
                eventType: 'payment.settled',
                payload: {
                    event: 'payment.settled',
                    subscription_id,
                    customer_wallet_address: sub.customer_wallet_address,
                    amount: settledAmount,
                    txHash,
                    settled_at: pullTime.toISOString(),
                },
                fetchImpl: app.locals.fetchImpl,
            });

            // Automated revenue sharing (#160): forward each configured split
            // share from the merchant treasury, recording the primary pull hash
            // next to every secondary split transfer hash. Failures here never
            // fail the settlement itself.
            try {
                await getPayoutSplitDispatcher().handlePaymentSettled({
                    merchantId: sub.plans.merchant_id,
                    subscriptionId: subscription_id,
                    primaryTxHash: txHash,
                    amountUnits: settledAmount,
                    settledAt: pullTime.toISOString(),
                    fetchImpl: app.locals.fetchImpl,
                });
            } catch (splitErr) {
                console.error("Payout split dispatch failed:", splitErr);
            }
        }

        return {
            status: 200,
            body: { message: "Successfully pulled funds on-chain!", txHash, ...extraBody },
        };
    }

    if (status === "FAILED") {
        if (server && signedTx) {
            let failureReason = 'Transaction failed on-chain; inspect transaction diagnostics for the specific contract error.';
            try {
                const simulation = await server.simulateTransaction(signedTx);
                if (simulation?.error) failureReason = simulation.error;
            } catch {
                // Keep the original failure when RPC diagnostics are unavailable
            }
            await recordPullFailure(supabase, subscription_id, failureReason, txHash);
        }
        await recordPullFailure(supabase, subscription_id, 'Transaction failed on-chain; inspect transaction diagnostics for the specific contract error.', txHash);
        await markSubscriptionPastDue(supabase, subscription_id, {
            actorAddress: merchant.wallet_address,
            ipAddress: getClientIp(req),
            fetchImpl: app.locals.fetchImpl,
        });

        return {
            status: 502,
            body: { error: "Transaction failed on-chain", txHash, ...extraBody },
        };
    }

    // Still NOT_FOUND after the timeout: outcome unknown, let the caller poll later.
    // Keep the lease until it expires so no second pull races the one still in flight.
    if (server && signedTx) {
        await recordPullFailure(
            supabase,
            subscription_id,
            'Transaction submitted, but Soroban RPC confirmation timed out (NOT_FOUND)',
            txHash,
        );
    }
    await recordPullFailure(supabase, subscription_id, 'RPC timeout: transaction submitted but not yet confirmed. Do not retry until its outcome is known.', txHash);
    return {
        status: 202,
        body: { message: "Transaction submitted but not yet confirmed; check back later", txHash, ...extraBody },
        holdLock: true,
    };
};

app.post('/trigger-pull', authenticateMerchant, async (req, res) => {
    const parseResult = triggerPullSchema.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    let ownedSubscriptionId;
    try {
        const { subscription_id } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const context = await loadPullContext(supabase, subscription_id, req.merchant);
        if (context.error) return res.status(context.status).json({ error: context.error });
        const { sub, merchant } = context;
        ownedSubscriptionId = subscription_id;

        const result = await executeIdempotently({
            supabase,
            req,
            label: "preparing pull",
            resolveMerchant: () => ({ merchantId: sub.plans.merchant_id }),
        }, async () => {
            // Price the pull (#96): fiat plans convert price_amount into raw
            // USDC units at the live rate and are rejected when the rate moved
            // more than the slippage tolerance away from the quoted rate.
            let pricing;
            try {
                pricing = await quoteUsdcAmount({
                    supabase,
                    plan: sub.plans,
                    subscription: sub,
                    fetchImpl: app.locals.fetchImpl,
                });
            } catch (err) {
                if (err instanceof SlippageError) {
                    return { status: 409, body: { error: err.message, ...err.details } };
                }
                if (err instanceof RateUnavailableError) {
                    return { status: 503, body: { error: err.message } };
                }
                throw err;
            }

            // A fiat subscription created while the rate cache was cold has no
            // quote yet: store this pull's rate so the next one is guarded.
            if (
                isFiatCurrency(sub.plans?.currency) &&
                pricing.rate != null &&
                (sub.quoted_rate === null || sub.quoted_rate === undefined)
            ) {
                const { error: quoteError } = await supabase
                    .from('subscriptions')
                    .update({ quoted_rate: pricing.rate })
                    .eq('id', subscription_id);
                if (quoteError) console.error("Failed to persist subscription quote:", quoteError.message);
            }

            return withBillingLock({
                supabase,
                subscriptionId: subscription_id,
                ttlSeconds: PREPARE_LOCK_TTL_SECONDS,
            }, async () => {
                const ORBIT_CONTRACT_ID = process.env.ORBIT_CONTRACT_ID;
                if (!ORBIT_CONTRACT_ID) {
                    return { status: 500, body: { error: "ORBIT_CONTRACT_ID not set in .env" } };
                }

                const rpcUrl = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
                const server = getSorobanServer(rpcUrl);
                const contract = new Contract(ORBIT_CONTRACT_ID);

                // 3. Build the Soroban Transaction
                const account = await server.getAccount(merchant.wallet_address);

                const tx = new TransactionBuilder(account, {
                    fee: "1000000",
                    networkPassphrase: process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET
                })
                .addOperation(contract.call("pull_funds",
                    Address.fromString(sub.customer_wallet_address).toScVal(),
                    Address.fromString(merchant.wallet_address).toScVal()
                ))
                .setTimeout(30)
                .build();

                // Simulate and return an unsigned envelope. The merchant signs it in their wallet.
                const preparedTx = await server.prepareTransaction(tx);

                await writeAuditLog(supabase, {
                    merchantId: sub.plans.merchant_id,
                    actorAddress: getActorAddress(req, merchant.wallet_address),
                    action: 'pull.prepare',
                    resourceType: 'subscription',
                    resourceId: subscription_id,
                    ipAddress: getClientIp(req),
                    changesBefore: null,
                    changesAfter: { subscription_id, merchant_address: merchant.wallet_address },
                });

                return {
                    status: 200,
                    body: {
                        transaction_xdr: preparedTx.toXDR(),
                        network_passphrase: process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET,
                        merchant_address: merchant.wallet_address,
                        subscription_id,
                        // Amount to settle this cycle (raw USDC units)
                        usdc_amount: pricing.usdc_amount,
                        currency: pricing.currency,
                        rate: pricing.rate,
                    },
                };
            });
        });
        if (result.status >= 500) await recordPullFailure(supabase, subscription_id, result.body?.error || 'Pull preparation failed');
        sendResult(res, result);
    } catch (err) {
        console.error("Error preparing pull:", err);
        if (ownedSubscriptionId) await recordPullFailure(getSupabase(), ownedSubscriptionId, err.message).catch(console.error);
        res.status(500).json({ error: err.message });
    }
});

// Accept only a wallet-signed envelope, verify the merchant signature, then submit it.
app.post('/submit-pull', authenticateMerchant, async (req, res) => {
    const parseResult = submitPullSchema.safeParse(req.body);
    if (!parseResult.success) return res.status(400).json({ error: formatZodError(parseResult.error) });

    let ownedSubscriptionId;
    try {
        const { subscription_id, signed_xdr } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
        const context = await loadPullContext(supabase, subscription_id, req.merchant);
        if (context.error) return res.status(context.status).json({ error: context.error });
        const { sub, merchant } = context;
        ownedSubscriptionId = subscription_id;

        const pollTimeoutMs = app.locals.txPollTimeoutMs ?? TX_POLL_TIMEOUT_MS;

        const result = await executeIdempotently({
            supabase,
            req,
            label: "submitting pull",
            resolveMerchant: () => ({ merchantId: sub.plans.merchant_id }),
        }, async () => {
            const networkPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET;
            let signedTx;
            try {
                signedTx = TransactionBuilder.fromXDR(signed_xdr, networkPassphrase);
            } catch {
                return { status: 400, body: { error: "signed_xdr is not a valid Stellar transaction envelope" } };
            }
            if (signedTx.source !== merchant.wallet_address) {
                return { status: 401, body: { error: "Transaction source does not match the plan owner's address" } };
            }
            const invocation = signedTx.operations.length === 1 && signedTx.operations[0].type === 'invokeHostFunction'
                ? signedTx.operations[0].func?.invokeContract
                : null;
            const isExpectedPull = invocation
                && invocation.functionName.toString() === 'pull_funds'
                && StrKey.encodeContract(invocation.contractAddress.contractId.value) === process.env.ORBIT_CONTRACT_ID
                && invocation.args.length === 2
                && Address.fromScVal(invocation.args[0]).toString() === sub.customer_wallet_address
                && Address.fromScVal(invocation.args[1]).toString() === merchant.wallet_address;
            if (!isExpectedPull) {
                return { status: 400, body: { error: "Signed transaction does not match this subscription's pull" } };
            }
            const merchantKey = Keypair.fromPublicKey(merchant.wallet_address);
            const hasMerchantSignature = signedTx.signatures.some(({ signature }) =>
                merchantKey.verify(signedTx.hash(), signature.value)
            );
            if (!hasMerchantSignature) {
                return { status: 401, body: { error: "A valid merchant wallet signature is required" } };
            }

            // Only one submission per subscription may be in flight at a time
            return withBillingLock({
                supabase,
                subscriptionId: subscription_id,
                ttlSeconds: submitLockTtlSeconds(pollTimeoutMs),
            }, async () => {
                const server = getSorobanServer(process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org');
                const submitResponse = await server.sendTransaction(signedTx);

                if (submitResponse.status !== "PENDING" && submitResponse.status !== "SUCCESS") {
                    throw new Error(`Transaction submission failed: ${JSON.stringify(submitResponse)}`);
                }

                const txHash = submitResponse.hash;

                // 5. Confirm the transaction actually landed before touching billing state
                const confirmation = await waitForTransaction(server, txHash, {
                    timeoutMs: pollTimeoutMs,
                    intervalMs: app.locals.txPollIntervalMs ?? TX_POLL_INTERVAL_MS,
                });

                return applyPullOutcome({
                    supabase,
                    req,
                    sub,
                    merchant,
                    subscription_id,
                    txHash,
                    status: confirmation.status,
                    confirmation,
                    server,
                    signedTx,
                });
                return applyPullOutcome({ supabase, req, sub, merchant, subscription_id, txHash, status: confirmation.status, confirmation });
            });
        });
        sendResult(res, result);
    } catch (err) {
        console.error("Error submitting pull:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 4b: Sponsored pulls through the fee-bump relayer
// ==========================================
// The merchant signs only the Soroban authorization for pull_funds; the Orbit relayer
// submits the transaction and pays its fees, so the merchant wallet needs no XLM for fees.

const relayerErrorResult = (err) => ({
    status: err.status,
    body: { error: err.message, code: err.code },
    headers: err.retryAfter ? { 'Retry-After': String(err.retryAfter) } : undefined,
});

const RELAYER_NOT_CONFIGURED = { error: "Gas sponsorship relayer is not configured", code: "relayer_unavailable" };

app.post('/relay/prepare-pull', authenticateMerchant, relayRateLimit, async (req, res) => {
    const parseResult = triggerPullSchema.safeParse(req.body);
    if (!parseResult.success) return res.status(400).json({ error: formatZodError(parseResult.error) });

    try {
        const { subscription_id } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
        const relayer = getRelayer();
        if (!relayer) return res.status(503).json(RELAYER_NOT_CONFIGURED);

        const context = await loadPullContext(supabase, subscription_id, req.merchant);
        if (context.error) return res.status(context.status).json({ error: context.error });
        const { sub, merchant } = context;

        let prepared;
        try {
            prepared = await relayer.preparePullAuthorization({
                user: sub.customer_wallet_address,
                merchant: merchant.wallet_address,
            });
        } catch (err) {
            if (isRelayerError(err)) return sendResult(res, relayerErrorResult(err));
            throw err;
        }

        res.status(200).json({
            auth_entry_xdr: prepared.authEntryXdr,
            valid_until_ledger: prepared.validUntilLedger,
            network_passphrase: process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET,
            merchant_address: merchant.wallet_address,
            sponsor_address: relayer.sponsorAddress,
            subscription_id,
        });
    } catch (err) {
        console.error("Error preparing sponsored pull:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/relay/submit-pull', authenticateMerchant, relayRateLimit, async (req, res) => {
    const parseResult = relaySubmitPullSchema.safeParse(req.body);
    if (!parseResult.success) return res.status(400).json({ error: formatZodError(parseResult.error) });

    try {
        const { subscription_id, signed_auth_entry_xdr } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
        const relayer = getRelayer();
        if (!relayer) return res.status(503).json(RELAYER_NOT_CONFIGURED);

        const context = await loadPullContext(supabase, subscription_id, req.merchant);
        if (context.error) return res.status(context.status).json({ error: context.error });
        const { sub, merchant } = context;

        const pollTimeoutMs = app.locals.txPollTimeoutMs ?? TX_POLL_TIMEOUT_MS;
        const pullParties = { user: sub.customer_wallet_address, merchant: merchant.wallet_address };

        const result = await executeIdempotently({
            supabase,
            req,
            label: "relaying pull",
            resolveMerchant: () => ({ merchantId: sub.plans.merchant_id }),
        }, async () => {
            let entry;
            try {
                entry = await relayer.verifyPullAuthorization({ entryXdr: signed_auth_entry_xdr, ...pullParties });
            } catch (err) {
                if (isRelayerError(err)) return relayerErrorResult(err);
                throw err;
            }

            return withBillingLock({
                supabase,
                subscriptionId: subscription_id,
                ttlSeconds: relayLockTtlSeconds(pollTimeoutMs),
            }, async () => {
                let outcome;
                try {
                    outcome = await relayer.relayPull({
                        merchantId: merchant.id,
                        entry,
                        ...pullParties,
                        confirm: (server, hash) => waitForTransaction(server, hash, {
                            timeoutMs: pollTimeoutMs,
                            intervalMs: app.locals.txPollIntervalMs ?? TX_POLL_INTERVAL_MS,
                        }),
                    });
                } catch (err) {
                    if (isRelayerError(err)) return relayerErrorResult(err);
                    throw err;
                }

                return applyPullOutcome({
                    supabase, req, sub, merchant, subscription_id,
                    txHash: outcome.txHash,
                    status: outcome.status,
                    extraBody: {
                        sponsored: true,
                        sponsor_address: relayer.sponsorAddress,
                        fee_charged_stroops: outcome.feeCharged,
                        attempts: outcome.attempts,
                    },
                });
            });
        });
        if (result.status >= 500 && !result.body?.txHash) await recordPullFailure(supabase, subscription_id, result.body?.error || 'Pull submission failed');
        sendResult(res, result);
    } catch (err) {
        console.error("Error relaying pull:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/relay/budget', authenticateMerchant, async (req, res) => {
    try {
        if (!getSupabase()) return res.status(500).json({ error: "Supabase client not initialized" });
        const relayer = getRelayer();
        if (!relayer) return res.status(503).json(RELAYER_NOT_CONFIGURED);

        res.status(200).json({ budget: await relayer.budgetStatus(req.merchant.id) });
    } catch (err) {
        console.error("Error fetching relayer budget:", err);
        console.error("Error submitting pull:", err);
        if (ownedSubscriptionId) await recordPullFailure(getSupabase(), ownedSubscriptionId, err.message).catch(console.error);
        res.status(500).json({ error: err.message });
    }
});

/**
 * POST /relay/sponsor-transaction (#169)
 * Allows the checkout widget to submit atomic batch transactions sponsored by the relayer.
 */
app.post('/relay/sponsor-transaction', relayRateLimit, async (req, res) => {
    try {
        const { tx_xdr, network_passphrase } = req.body || {};
        if (!tx_xdr) return res.status(400).json({ error: 'tx_xdr is required' });
        const relayer = getRelayer();
        if (!relayer) return res.status(503).json(RELAYER_NOT_CONFIGURED);

        const result = await relayer.sponsorTransaction({
            txXdr: tx_xdr,
            passphrase: network_passphrase || process.env.STELLAR_NETWORK_PASSPHRASE || Networks.TESTNET,
        });
        return res.status(200).json(result);
    } catch (err) {
        console.error('Error sponsoring transaction:', err);
        return res.status(500).json({ error: err.message || 'Fee sponsorship failed' });
    }
});

// ==========================================
// ROUTE 5: POST /subscriptions (Create Subscription after Handshake)
// ==========================================
app.post('/subscriptions', async (req, res) => {
    const parseResult = createSubscriptionSchema.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    const { plan_id, customer_wallet_address, metadata, coupon_code } = parseResult.data;
    const supabase = getPrimarySupabase();
    if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
    if (!dbManager.isPrimaryHealthy()) {
        return res.status(503).json({ error: "Primary database is currently unavailable; write operations are suspended" });
    }

    const result = await executeIdempotently({
        supabase,
        req,
        label: "creating subscription",
        // Idempotency keys are scoped to the merchant that owns the plan
        resolveMerchant: async () => {
            const { data: plan, error } = await supabase
                .from('plans')
                .select('merchant_id')
                .eq('id', plan_id)
                .single();
            if (isNoRowsError(error) || !plan) return { status: 404, body: { error: "Plan not found" } };
            if (error) throw error;
            return { merchantId: plan.merchant_id };
        },
    }, async () => {
        const nextBillingDate = new Date().toISOString();

        // Look up the plan so fiat plans can capture the oracle rate as their
        // slippage quote. Non-fatal: the insert below still verifies the plan
        // through its foreign key.
        let planRow = null;
        try {
            const { data: planData, error: planLookupError } = await supabase
                .from('plans')
                .select('merchant_id, currency, price_amount, usdc_amount')
                .eq('id', plan_id);
            if (planLookupError) throw planLookupError;
            planRow = Array.isArray(planData) ? planData[0] : planData || null;
        } catch (err) {
            console.error("Error loading plan for subscription:", err.message);
        }

        const insertPayload = {
            plan_id,
            customer_wallet_address,
            next_billing_date: nextBillingDate,
            metadata: metadata || {},
        };

        // Fiat plans: quote the fiat->USDC rate now. The pull flow later
        // rejects settlements whose live rate moves more than 2% from it.
        if (isFiatCurrency(planRow?.currency)) {
            try {
                const quote = await quoteUsdcAmount({
                    supabase,
                    plan: planRow,
                    fetchImpl: app.locals.fetchImpl,
                    allowNetwork: false,
                    enforceSlippage: false,
                });
                insertPayload.quoted_rate = quote.rate;
            } catch (err) {
                // Cold rate cache: subscribe without a quote; the first pull stores one
                console.error("Unable to quote subscription exchange rate:", err.message);
            }
        }

        // A SQL function locks the coupon and atomically creates the
        // subscription and increments redemptions_count; no read-then-write race.
        let data, error;
        if (coupon_code) {
            const redeemed = await supabase.rpc('redeem_coupon_subscription', {
                p_plan_id: plan_id,
                p_customer_wallet_address: customer_wallet_address,
                p_metadata: metadata || {},
                p_code: normalizeCode(coupon_code),
                p_quoted_rate: insertPayload.quoted_rate ?? null,
            });
            data = Array.isArray(redeemed.data) ? redeemed.data[0] : redeemed.data;
            error = redeemed.error;
            if (error?.code === 'P7501') return { status: 422, body: { error: 'Coupon invalid or incompatible with plan' } };
            if (error?.code === 'P7502') return { status: 409, body: { error: 'Coupon redemption limit reached' } };
            if (error?.code === 'P7503') return { status: 404, body: { error: 'Plan not found' } };
        } else {
            ({ data, error } = await supabase.from('subscriptions')
                .insert([insertPayload]).select().single());
        }

        if (isForeignKeyError(error)) return { status: 404, body: { error: "Plan not found" } };
        if (isUniqueViolation(error)) {
            return { status: 409, body: { error: "This wallet is already subscribed to this plan" } };
        }
        if (error) throw error;

        // Fetch merchant id from plan to scope audit & webhook
        const { data: planData } = await supabase
            .from('plans')
            .select('merchant_id')
            .eq('id', plan_id)
            .single();

        const merchantId = planData?.merchant_id;

        await writeAuditLog(supabase, {
            merchantId,
            actorAddress: getActorAddress(req, customer_wallet_address),
            action: 'subscription.create',
            resourceType: 'subscription',
            resourceId: data.id,
            ipAddress: getClientIp(req),
            changesBefore: null,
            changesAfter: data,
        });

        if (merchantId) {
            await dispatchWebhookEvent(supabase, {
                merchantId,
                eventType: 'subscription.created',
                payload: {
                    event: 'subscription.created',
                    subscription_id: data.id,
                    customer_wallet_address,
                    plan_id,
                    next_billing_date: nextBillingDate,
                },
                fetchImpl: app.locals.fetchImpl,
            });
        }

        return { status: 201, body: { message: "Subscription created", subscription: data } };
    });
    sendResult(res, result);
});

// ==========================================
// ROUTE 6: API key management (authenticated with an existing key)
// ==========================================
// The first key for a merchant is issued out of band with `npm run create-api-key`.

const API_KEY_COLUMNS = 'id, name, key_prefix, environment, created_at, last_used_at, revoked_at';

// Not wrapped in executeIdempotently: that would persist the one-time secret in idempotency_keys
app.post('/api-keys', authenticateMerchant, async (req, res) => {
    const parseResult = createApiKeySchema.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    const { name, environment } = parseResult.data;
    // A test key must not be able to escalate itself into live credentials
    if (environment === 'live' && req.apiKey.environment !== 'live') {
        return res.status(403).json({ error: "Live API keys can only be created with a live API key" });
    }

    try {
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { apiKey, secret, error } = await issueApiKey(supabase, { merchantId: req.merchant.id, name, environment });
        if (error) throw error;

        await writeAuditLog(supabase, {
            merchantId: req.merchant.id,
            actorAddress: getActorAddress(req, null),
            action: 'api_key.create',
            resourceType: 'api_key',
            resourceId: apiKey.id,
            ipAddress: getClientIp(req),
            changesBefore: null,
            changesAfter: { name, environment, key_prefix: apiKey.key_prefix },
        });

        res.set('Cache-Control', 'no-store');
        res.status(201).json({
            message: "API key created. Store the secret now; it will not be shown again.",
            api_key: apiKey,
            secret,
        });
    } catch (err) {
        console.error("Error creating API key:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api-keys', authenticateMerchant, async (req, res) => {
    try {
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data, error } = await supabase
            .from('api_keys')
            .select(API_KEY_COLUMNS)
            .eq('merchant_id', req.merchant.id)
            .order('created_at', { ascending: false });
        if (error) throw error;

        res.status(200).json({ api_keys: data });
    } catch (err) {
        console.error("Error listing API keys:", err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api-keys/:id', authenticateMerchant, async (req, res) => {
    const parseResult = apiKeyParamsSchema.safeParse(req.params);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        // Scoped by merchant_id so one merchant can never revoke another's key
        const { data, error } = await supabase
            .from('api_keys')
            .update({ revoked_at: new Date().toISOString() })
            .eq('id', parseResult.data.id)
            .eq('merchant_id', req.merchant.id)
            .is('revoked_at', null)
            .select(API_KEY_COLUMNS)
            .maybeSingle();
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "API key not found or already revoked" });

        await writeAuditLog(supabase, {
            merchantId: req.merchant.id,
            actorAddress: getActorAddress(req, null),
            action: 'api_key.revoke',
            resourceType: 'api_key',
            resourceId: parseResult.data.id,
            ipAddress: getClientIp(req),
            changesBefore: data,
            changesAfter: { revoked_at: data.revoked_at },
        });

        res.status(200).json({ message: "API key revoked", api_key: data });
    } catch (err) {
        console.error("Error revoking API key:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 7: GET /audit-logs (Compliance & Forensic Audit Trail)
// ==========================================
app.get('/audit-logs', async (req, res) => {
    const parseResult = getAuditLogsQuerySchema.safeParse(req.query);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const { merchant_id, action, resource_type, start_date, end_date, limit, offset } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        let query = supabase
            .from('audit_logs')
            .select('*', { count: 'exact' })
            .eq('merchant_id', merchant_id);

        if (action) query = query.eq('action', action);
        if (resource_type) query = query.eq('resource_type', resource_type);
        if (start_date) query = query.gte('created_at', start_date);
        if (end_date) query = query.lte('created_at', end_date);

        query = query.order('created_at', { ascending: false }).range(offset, offset + limit - 1);

        const { data, count, error } = await query;
        if (error) throw error;

        res.status(200).json({
            audit_logs: data || [],
            total: count ?? (data?.length || 0),
            limit,
            offset,
        });
    } catch (err) {
        console.error("Error fetching audit logs:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 8: DUNNING MANAGEMENT & RECOVERY
// ==========================================
app.post('/dunning/process', async (req, res) => {
    try {
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });
        const merchant_id = req.body?.merchant_id;
        // Use the merchant's saved dunning workflow when one exists (#190)
        const workflow = await loadDunningWorkflow(supabase, merchant_id);
        const result = await processDunningRetries(supabase, {
            merchantId: merchant_id,
            fetchImpl: app.locals.fetchImpl,
            workflowSteps: workflow?.steps || null,
        });
        res.status(200).json(result);
    } catch (err) {
        console.error("Error processing dunning retries:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/subscriptions/:id/recovery-link', authenticateMerchant, async (req, res) => {
    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: sub, error } = await supabase
            .from('subscriptions')
            .select('*, plans(*)')
            .eq('id', id)
            .single();

        if (isNoRowsError(error) || !sub) return res.status(404).json({ error: "Subscription not found" });
        if (error) throw error;
        // Never disclose whether another merchant owns this subscription.
        if (sub.plans?.merchant_id !== req.merchant.id) {
            return res.status(404).json({ error: "Subscription not found" });
        }

        if (sub.plans?.merchant_id !== req.merchant.id) return res.status(404).json({ error: 'Subscription not found' });

        const recovery = generateRecoveryLink(id, { planId: sub.plan_id });
        res.status(200).json(recovery);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 8: CUSTOMER MANAGEMENT ACTIONS
// ==========================================
app.post('/subscriptions/:id/cancel', authenticateMerchant, async (req, res) => {
    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: sub, error } = await supabase
            .from('subscriptions')
            .select('*, plans(*)')
            .eq('id', id)
            .single();

        if (isNoRowsError(error) || !sub) return res.status(404).json({ error: "Subscription not found" });
        if (error) throw error;
        // Never disclose whether another merchant owns this subscription.
        if (sub.plans?.merchant_id !== req.merchant.id) {
            return res.status(404).json({ error: "Subscription not found" });
        }

        const changesBefore = { status: sub.status };
        const changesAfter = { status: 'cancelled', next_dunning_retry_at: null };

        const { data: updated, error: updateErr } = await supabase
            .from('subscriptions')
            .update(changesAfter)
            .eq('id', id)
            .select()
            .single();

        if (updateErr) throw updateErr;

        const merchantId = sub.plans?.merchant_id;
        await writeAuditLog(supabase, {
            merchantId,
            actorAddress: getActorAddress(req, sub.customer_wallet_address),
            action: 'subscription.cancel',
            resourceType: 'subscription',
            resourceId: id,
            ipAddress: getClientIp(req),
            changesBefore,
            changesAfter,
        });

        if (merchantId) {
            await dispatchWebhookEvent(supabase, {
                merchantId,
                eventType: 'subscription.cancelled',
                payload: {
                    event: 'subscription.cancelled',
                    subscription_id: id,
                    customer_wallet_address: sub.customer_wallet_address,
                    reason: req.body?.reason || 'merchant_requested',
                },
                fetchImpl: app.locals.fetchImpl,
            });
        }

        res.status(200).json({ message: "Subscription cancelled successfully", subscription: updated });
    } catch (err) {
        console.error("Error cancelling subscription:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/subscriptions/:id/refund', authenticateMerchant, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, reason, prorated } = req.body || {};
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: sub, error } = await supabase
            .from('subscriptions')
            .select('*, plans(*)')
            .eq('id', id)
            .single();

        if (isNoRowsError(error) || !sub) return res.status(404).json({ error: "Subscription not found" });
        if (error) throw error;
        // Never disclose whether another merchant owns this subscription.
        if (sub.plans?.merchant_id !== req.merchant.id) {
            return res.status(404).json({ error: "Subscription not found" });
        }

        const merchantId = sub.plans?.merchant_id;
        const refundAmount = amount ?? sub.plans?.usdc_amount;

        await writeAuditLog(supabase, {
            merchantId,
            actorAddress: getActorAddress(req, sub.customer_wallet_address),
            action: 'subscription.refund',
            resourceType: 'subscription',
            resourceId: id,
            ipAddress: getClientIp(req),
            changesBefore: null,
            changesAfter: { amount: refundAmount, reason, prorated: !!prorated },
        });

        if (merchantId) {
            await dispatchWebhookEvent(supabase, {
                merchantId,
                eventType: 'payment.refunded',
                payload: {
                    event: 'payment.refunded',
                    subscription_id: id,
                    customer_wallet_address: sub.customer_wallet_address,
                    refund_amount: refundAmount,
                    reason: reason || 'Customer refund request',
                    prorated: !!prorated,
                },
                fetchImpl: app.locals.fetchImpl,
            });
        }

        res.status(200).json({
            message: "Refund processed successfully",
            refund: {
                subscription_id: id,
                amount: refundAmount,
                reason: reason || 'Customer refund request',
                prorated: !!prorated,
            },
        });
    } catch (err) {
        console.error("Error processing refund:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/subscriptions/:id/timeline', authenticateMerchant, async (req, res) => {
    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: sub, error } = await supabase
            .from('subscriptions')
            .select('*, plans(*)')
            .eq('id', id)
            .single();

        if (isNoRowsError(error) || !sub) return res.status(404).json({ error: "Subscription not found" });
        if (error) throw error;
        // Never disclose whether another merchant owns this subscription.
        if (sub.plans?.merchant_id !== req.merchant.id) {
            return res.status(404).json({ error: "Subscription not found" });
        }

        const { data: logs } = await supabase
            .from('audit_logs')
            .select('*')
            .eq('resource_id', id)
            .order('created_at', { ascending: false });

        const timeline = [];

        timeline.push({
            id: `created-${id}`,
            type: 'subscription_created',
            title: 'Vault Handshake Established',
            description: `Subscriber linked Ed25519 wallet to ${sub.plans?.name || 'plan'}`,
            timestamp: sub.created_at || new Date().toISOString(),
            status: 'success',
        });

        if (logs && Array.isArray(logs)) {
            for (const log of logs) {
                if (log.action === 'pull.execute') {
                    timeline.push({
                        id: log.id,
                        type: 'settled_pull',
                        title: 'Recurring USDC Pull Settled',
                        description: 'Contract executed pull_funds with 1.2s Soroban consensus finality',
                        amount: sub.plans?.usdc_amount,
                        timestamp: log.created_at,
                        status: 'success',
                        txHash: log.changes_after?.txHash,
                    });
                } else if (log.action === 'subscription.past_due') {
                    timeline.push({
                        id: log.id,
                        type: 'failed_pull',
                        title: 'Pull Attempt Failed',
                        description: 'Account balance insufficient or allowance limit reached. Dunning cycle started.',
                        timestamp: log.created_at,
                        status: 'failed',
                    });
                } else if (log.action === 'subscription.dunning_retry') {
                    timeline.push({
                        id: log.id,
                        type: 'dunning_retry',
                        title: `Automated Dunning Attempt #${log.changes_after?.retry_count || 1}`,
                        description: 'Smart recovery schedule retry triggered with merchant webhook dispatch.',
                        timestamp: log.created_at,
                        status: 'warning',
                    });
                } else if (log.action === 'subscription.refund') {
                    timeline.push({
                        id: log.id,
                        type: 'refund',
                        title: 'Prorated Refund Issued',
                        description: `Refund credited back to subscriber (${log.changes_after?.reason || 'merchant initiated'})`,
                        amount: log.changes_after?.amount,
                        timestamp: log.created_at,
                        status: 'info',
                    });
                } else if (log.action === 'subscription.cancel' || log.action === 'subscription.dunning_cancelled') {
                    timeline.push({
                        id: log.id,
                        type: 'cancelled',
                        title: log.action === 'subscription.dunning_cancelled' ? 'Cancelled (Dunning Expired)' : 'Subscription Cancelled',
                        description: 'Vault allowance revoked and recurrence stopped.',
                        timestamp: log.created_at,
                        status: 'failed',
                    });
                }
            }
        }

        timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        res.status(200).json({ timeline, subscription: sub });
    } catch (err) {
        console.error("Error fetching timeline:", err);
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ROUTE 9: WEBHOOK MANAGEMENT & DELIVERY LOGS
// ==========================================
app.get('/webhooks', async (req, res) => {
    try {
        const { merchant_id } = req.query;
        if (!merchant_id) return res.status(400).json({ error: "merchant_id is required" });
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data, error } = await supabase
            .from('webhooks')
            .select('*')
            .eq('merchant_id', merchant_id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.status(200).json({ webhooks: data || [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/webhooks', async (req, res) => {
    const parseResult = createWebhookSchema.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const { merchant_id, url, events, signing_secret } = parseResult.data;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const secret = signing_secret || generateSigningSecret();
        const { data, error } = await supabase
            .from('webhooks')
            .insert([{
                merchant_id,
                url,
                events,
                signing_secret: secret,
                active: true,
            }])
            .select()
            .single();

        if (isForeignKeyError(error)) return res.status(404).json({ error: "Merchant not found" });
        if (error) throw error;

        await writeAuditLog(supabase, {
            merchantId: merchant_id,
            actorAddress: getActorAddress(req, null),
            action: 'webhook.create',
            resourceType: 'webhook',
            resourceId: data.id,
            ipAddress: getClientIp(req),
            changesBefore: null,
            changesAfter: { url, events, active: true },
        });

        res.status(201).json({ message: "Webhook created successfully", webhook: data });
    } catch (err) {
        console.error("Error creating webhook:", err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/webhooks/:id', async (req, res) => {
    const parseResult = updateWebhookSchema.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: existing, error: existErr } = await supabase
            .from('webhooks')
            .select('*')
            .eq('id', id)
            .single();

        if (isNoRowsError(existErr) || !existing) return res.status(404).json({ error: "Webhook not found" });
        if (existErr) throw existErr;

        const updateData = {};
        if (parseResult.data.url !== undefined) updateData.url = parseResult.data.url;
        if (parseResult.data.events !== undefined) updateData.events = parseResult.data.events;
        if (parseResult.data.active !== undefined) updateData.active = parseResult.data.active;
        if (parseResult.data.signing_secret !== undefined) updateData.signing_secret = parseResult.data.signing_secret;

        const { data: updated, error: updateErr } = await supabase
            .from('webhooks')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();

        if (updateErr) throw updateErr;

        await writeAuditLog(supabase, {
            merchantId: existing.merchant_id,
            actorAddress: getActorAddress(req, null),
            action: 'webhook.update',
            resourceType: 'webhook',
            resourceId: id,
            ipAddress: getClientIp(req),
            changesBefore: existing,
            changesAfter: updated,
        });

        res.status(200).json({ message: "Webhook updated successfully", webhook: updated });
    } catch (err) {
        console.error("Error updating webhook:", err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/webhooks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { data: existing, error: existErr } = await supabase
            .from('webhooks')
            .select('*')
            .eq('id', id)
            .single();

        if (isNoRowsError(existErr) || !existing) return res.status(404).json({ error: "Webhook not found" });
        if (existErr) throw existErr;

        const { error: delErr } = await supabase
            .from('webhooks')
            .delete()
            .eq('id', id);

        if (delErr) throw delErr;

        await writeAuditLog(supabase, {
            merchantId: existing.merchant_id,
            actorAddress: getActorAddress(req, null),
            action: 'webhook.delete',
            resourceType: 'webhook',
            resourceId: id,
            ipAddress: getClientIp(req),
            changesBefore: existing,
            changesAfter: null,
        });

        res.status(200).json({ message: "Webhook deleted successfully" });
    } catch (err) {
        console.error("Error deleting webhook:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/webhooks/deliveries', async (req, res) => {
    try {
        const { merchant_id, webhook_id, limit = 50, offset = 0 } = req.query;
        if (!merchant_id) return res.status(400).json({ error: "merchant_id is required" });
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        let query = supabase
            .from('webhook_deliveries')
            .select('*, webhooks(url)', { count: 'exact' })
            .eq('merchant_id', merchant_id);

        if (webhook_id) query = query.eq('webhook_id', webhook_id);

        query = query
            .order('created_at', { ascending: false })
            .range(Number(offset), Number(offset) + Number(limit) - 1);

        const { data, count, error } = await query;
        if (error) throw error;

        res.status(200).json({
            deliveries: data || [],
            total: count ?? (data?.length || 0),
            limit: Number(limit),
            offset: Number(offset),
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/webhooks/deliveries/:id/resend', async (req, res) => {
    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const updated = await resendWebhookDelivery(supabase, id, app.locals.fetchImpl);
        if (!updated) return res.status(404).json({ error: "Delivery record not found" });

        res.status(200).json({ message: "Webhook redelivered successfully", delivery: updated });
    } catch (err) {
        console.error("Error resending webhook delivery:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/webhooks/test', async (req, res) => {
    try {
        const { merchant_id, webhook_id, event_type = "payment.settled" } = req.body || {};
        if (!merchant_id) return res.status(400).json({ error: "merchant_id is required" });
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const testPayload = {
            event: event_type,
            test: true,
            timestamp: new Date().toISOString(),
            data: {
                subscription_id: crypto.randomUUID(),
                customer_wallet_address: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                amount: 290000000,
                currency: "USDC",
                status: "success",
            },
        };

        const deliveries = await dispatchWebhookEvent(supabase, {
            merchantId: merchant_id,
            eventType: event_type,
            payload: testPayload,
            fetchImpl: app.locals.fetchImpl,
        });

        res.status(200).json({
            message: "Test webhook event triggered",
            dispatched_count: deliveries.length,
            deliveries,
        });
    } catch (err) {
        console.error("Error sending test webhook:", err);
        res.status(500).json({ error: err.message });
    }
});

// Rotate without downtime: keep the old secret for in-flight retries and use
// the new one for all subsequent deliveries.
app.post('/webhooks/:id/rotate-secret', async (req, res) => {
    const supabase = getSupabase();
    if (!supabase) return res.status(500).json({ error: 'Supabase client not initialized' });
    const secret = generateSigningSecret();
    const { data, error } = await supabase.from('webhooks').update({ previous_signing_secret: req.body?.signing_secret || null, signing_secret: secret, secret_rotated_at: new Date().toISOString() }).eq('id', req.params.id).select('id,secret_rotated_at').single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ webhook: data, signing_secret: secret });
});

app.post('/webhooks/:id/backfill', async (req, res) => {
    const parseResult = backfillWebhookSchema.safeParse(req.body || {});
    if (!parseResult.success) {
        return res.status(400).json({ error: formatZodError(parseResult.error) });
    }

    try {
        const { id } = req.params;
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

        const { event_types, start_date, end_date } = parseResult.data;
        const result = await replayWebhookEvents(supabase, {
            webhookId: id,
            eventTypes: event_types,
            startDate: start_date,
            endDate: end_date,
            fetchImpl: app.locals.fetchImpl,
        });

        res.status(200).json({
            message: "Webhook backfill completed successfully",
            total_events: result.total_events,
            replayed_count: result.replayed_count,
            deliveries: result.deliveries,
        });
    } catch (err) {
        if (err.status === 404 || err.message === 'Webhook not found') {
            return res.status(404).json({ error: "Webhook not found" });
        }
        console.error("Error executing webhook backfill:", err);
        res.status(500).json({ error: err.message });
    }
});

registerComplianceRoutes(app, getSupabase, authenticateMerchant);
registerRpcProxyRoute(app);
registerPrivacyRoutes(app, { getPrimarySupabase, authenticateMerchant });
registerProofRoutes(app, { getPrimarySupabase, authenticateMerchant });
registerSigningSessionRoutes(app, getSupabase, authenticateMerchant);

// Webhook incident alerting: Slack / PagerDuty / email channels and failure telemetry (#189)
registerWebhookAlertRoutes(app, getSupabase, authenticateMerchant);

// Dunning workflow builder: saved retry cadence, email templates and recovery funnel (#190)
registerDunningWorkflowRoutes(app, getSupabase, authenticateMerchant);
setDeliveryObserver(createDeliveryAlertObserver(getSupabase));
registerCustomerPortalRoutes(app, getSupabase, getSorobanServer);
registerFailureRecoveryRoutes(app, getSupabase, authenticateMerchant);
registerCouponRoutes(app, getSupabase, authenticateMerchant);
registerBillingResolutionRoutes(app, getSupabase, authenticateMerchant, loadPullContext, getSorobanServer);
registerPayoutSplitRoutes(app, getSupabase, authenticateMerchant, {
    resolveDispatcher: () => getPayoutSplitDispatcher(),
});
registerPriceIndexationRoutes(app, getSupabase, authenticateMerchant);
registerSnapshotRoutes(app, getSupabase, authenticateMerchant, getSorobanServer);
registerIndexerRoutes(app);
app.locals.graphqlServer = registerGraphql(app, getSupabase, authenticateMerchant);

// Merchant profile & custom contract persistence (#143)
app.get('/merchant/profile', authenticateMerchant, async (req, res) => {
    try {
        const supabase = getReadSupabase();
        if (!supabase) return res.status(500).json({ error: "Database client not initialized" });
        const { data, error } = await supabase
            .from('merchants')
            .select('id, name, wallet_address, contract_id, created_at')
            .eq('id', req.merchant.id)
            .single();
        if (error) throw error;
        res.status(200).json({ merchant: data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/merchant/profile', authenticateMerchant, async (req, res) => {
    try {
        const supabase = getPrimarySupabase();
        if (!supabase) return res.status(500).json({ error: "Database client not initialized" });
        if (!dbManager.isPrimaryHealthy()) {
            return res.status(503).json({ error: "Primary database is currently unavailable; write operations are suspended" });
        }
        const updates = {};
        if (typeof req.body?.name === 'string' && req.body.name.trim()) {
            updates.name = req.body.name.trim();
        }
        if (typeof req.body?.contract_id === 'string' && req.body.contract_id.trim()) {
            updates.contract_id = req.body.contract_id.trim();
        }
        const { data, error } = await supabase
            .from('merchants')
            .update(updates)
            .eq('id', req.merchant.id)
            .select('id, name, wallet_address, contract_id, created_at')
            .single();
        if (error) throw error;
        res.status(200).json({ merchant: data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PostgreSQL protocol cursor: unlike Supabase REST pagination, the cursor
// never materializes the full transaction table in application memory.
const getReportPool = () => {
    return dbManager.getReportPool(app, { readOnly: true });
};
registerTransactionExportRoute(
    app, authenticateMerchant, getReportPool,
    (sql, values) => {
        const Cursor = require('pg-cursor');
        return new Cursor(sql, values);
    },
);

const PORT = process.env.PORT || 3001;
if (require.main === module) {
    if (getSupabase() && process.env.INDEXER_START_LEDGER) {
        app.locals.ledgerIndexer = configuredIndexer(getSupabase());
        app.locals.indexerWorker = app.locals.ledgerIndexer.start(Number(process.env.INDEXER_INTERVAL_MS) || 5000);
    }
    // Background oracle worker (#96): refreshes the fiat->USDC rate cache on a
    // schedule so /rates and dynamic fiat billing always read fresh quotes.
    const oracleSupabase = getSupabase();
    if (oracleSupabase) {
        app.locals.oracleWorker = startOracleWorker({
            supabase: oracleSupabase,
            fetchImpl: app.locals.fetchImpl,
        });

        // Price indexation worker (#164): notifies subscribers inside the advance
        // notice window and applies scheduled plan price changes on their
        // effective date.
        app.locals.priceIndexationWorker = createPriceIndexationWorker({
            supabase: oracleSupabase,
            fetchImpl: app.locals.fetchImpl,
        });
        app.locals.priceIndexationWorker.start(
            Number(process.env.PRICE_INDEXATION_INTERVAL_MS) || undefined,
        );

        // Daily contract state snapshot backup worker (#185): exports Soroban
        // vaults, plans, and admin configs with SHA-256 integrity checksums.
        if (process.env.ORBIT_CONTRACT_ID || process.env.SOROBAN_CONTRACT_ID) {
            app.locals.snapshotExportWorker = createSnapshotExportWorker({
                server: getSorobanServer(process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org'),
                supabase: oracleSupabase,
                contractId: process.env.ORBIT_CONTRACT_ID || process.env.SOROBAN_CONTRACT_ID,
            });
            app.locals.snapshotExportWorker.start(
                Number(process.env.SNAPSHOT_EXPORT_INTERVAL_MS) || undefined,
            );
        }
    } else {
        console.warn("Oracle worker not started: Supabase client not initialized");
    }

    app.listen(PORT, () => {
        console.log(`Orbit Merchant API running on http://localhost:${PORT}`);
    });
}

module.exports = app;

