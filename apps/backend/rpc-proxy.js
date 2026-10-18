const { z } = require('zod');

const ALLOWED_METHODS = new Set(['getLedgerEntries', 'simulateTransaction', 'getLatestLedger']);
const CACHE_TTLS = Object.freeze({ getLedgerEntries: 30_000, getLatestLedger: 10_000 });
const rpcRequestSchema = z.object({
    jsonrpc: z.literal('2.0').optional(),
    id: z.union([z.string(), z.number(), z.null()]).optional(),
    method: z.string(),
    params: z.union([z.array(z.unknown()), z.record(z.string(), z.unknown())]).default([]),
});

class CircuitBreaker {
    constructor({ failureThreshold = 3, cooldownMs = 30_000 } = {}) {
        this.failureThreshold = failureThreshold;
        this.cooldownMs = cooldownMs;
        this.states = new Map();
    }
    available(url, now = Date.now()) { return (this.states.get(url)?.openUntil || 0) <= now; }
    success(url) { this.states.delete(url); }
    failure(url, now = Date.now()) {
        const current = this.states.get(url) || { failures: 0, openUntil: 0 };
        const failures = current.failures + 1;
        this.states.set(url, { failures, openUntil: failures >= this.failureThreshold ? now + this.cooldownMs : 0 });
    }
}

const cacheKey = (method, params) => `${method}:${JSON.stringify(params)}`;

function createRpcProxy({ urls, fetchImpl = globalThis.fetch, cache = new Map(), breaker = new CircuitBreaker(), now = () => Date.now() }) {
    const endpoints = [...new Set((urls || []).filter(Boolean))];
    if (!endpoints.length) throw new Error('At least one Soroban RPC URL is required');
    async function call({ method, params, id = null }) {
        if (!ALLOWED_METHODS.has(method)) {
            const error = new Error(`RPC method ${method} is not permitted`);
            error.statusCode = 400;
            throw error;
        }
        const key = cacheKey(method, params);
        const ttl = CACHE_TTLS[method];
        const cached = ttl && cache.get(key);
        if (cached && cached.expiresAt > now()) return { ...cached.body, id, cached: true };
        let lastError;
        for (const url of endpoints) {
            if (!breaker.available(url, now())) continue;
            try {
                const response = await fetchImpl(url, {
                    method: 'POST', headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
                });
                if (!response.ok) throw new Error(`RPC endpoint returned ${response.status}`);
                const body = await response.json();
                if (body.error) throw new Error(body.error.message || 'RPC response error');
                breaker.success(url);
                if (ttl) cache.set(key, { body: { ...body, id: null }, expiresAt: now() + ttl });
                return body;
            } catch (error) { breaker.failure(url, now()); lastError = error; }
        }
        const error = new Error(`Soroban RPC unavailable: ${lastError?.message || 'all endpoints are unhealthy'}`);
        error.statusCode = 503;
        throw error;
    }
    return { call, cache, breaker };
}

function createIpWindowLimiter({ limit = 60, windowMs = 60_000, now = () => Date.now() } = {}) {
    const counts = new Map();
    return (req, res, next) => {
        const key = req.ip || req.socket?.remoteAddress || 'unknown';
        const entry = counts.get(key);
        const time = now();
        const current = !entry || entry.resetAt <= time ? { count: 0, resetAt: time + windowMs } : entry;
        current.count += 1; counts.set(key, current);
        res.set('RateLimit-Limit', String(limit));
        res.set('RateLimit-Remaining', String(Math.max(0, limit - current.count)));
        if (current.count > limit) return res.status(429).json({ error: 'RPC proxy rate limit exceeded' });
        next();
    };
}

function registerRpcProxyRoute(app, { urls, fetchImpl, proxy } = {}) {
    const endpoints = urls || (process.env.SOROBAN_RPC_URLS || process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org').split(',').map((url) => url.trim());
    const service = proxy || createRpcProxy({ urls: endpoints, fetchImpl: fetchImpl || app.locals.fetchImpl || globalThis.fetch });
    app.locals.rpcProxy = service;
    app.post('/rpc/proxy', createIpWindowLimiter({ limit: Number(process.env.RPC_PROXY_RATE_LIMIT_MAX) || 60 }), async (req, res) => {
        const parsed = rpcRequestSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
        try {
            const body = await service.call(parsed.data);
            res.json(body);
        } catch (error) { res.status(error.statusCode || 502).json({ error: error.message }); }
    });
}

module.exports = { ALLOWED_METHODS, CACHE_TTLS, CircuitBreaker, createRpcProxy, createIpWindowLimiter, registerRpcProxyRoute };
