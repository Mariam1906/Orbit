const client = require('prom-client');

function createObservability({ getSupabase, getSorobanServer, rpcUrl, registry = new client.Registry() }) {
    client.collectDefaultMetrics({ register: registry, prefix: 'orbit_' });
    const httpLatency = new client.Histogram({ name: 'orbit_http_request_duration_seconds', help: 'HTTP request latency', labelNames: ['method', 'route', 'status'], registers: [registry] });
    const rpcLatency = new client.Histogram({ name: 'orbit_soroban_rpc_duration_seconds', help: 'Soroban RPC latency', labelNames: ['method', 'status'], registers: [registry] });
    const subscriptions = new client.Gauge({ name: 'orbit_subscriptions', help: 'Subscriptions by state', labelNames: ['state'], registers: [registry] });
    const failedPulls = new client.Gauge({ name: 'orbit_failed_pulls', help: 'Past-due subscriptions', registers: [registry] });
    async function ready() {
        const checks = {};
        try { const { error } = await getSupabase().from('merchants').select('id').limit(1); if (error) throw error; checks.supabase = 'ok'; } catch (e) { checks.supabase = e.message; }
        try { const started = process.hrtime.bigint(); await getSorobanServer(rpcUrl).getLatestLedger(); rpcLatency.observe({ method: 'getLatestLedger', status: 'ok' }, Number(process.hrtime.bigint() - started) / 1e9); checks.soroban_rpc = 'ok'; } catch (e) { rpcLatency.observe({ method: 'getLatestLedger', status: 'error' }, 0); checks.soroban_rpc = e.message; }
        return { ready: checks.supabase === 'ok' && checks.soroban_rpc === 'ok', checks };
    }
    async function collectBusinessMetrics() {
        try { const { count: active } = await getSupabase().from('subscriptions').select('*', { count: 'exact', head: true }).eq('status', 'active'); subscriptions.set({ state: 'active' }, active || 0); const { count: failed } = await getSupabase().from('subscriptions').select('*', { count: 'exact', head: true }).eq('status', 'past_due'); failedPulls.set(failed || 0); } catch { /* scrape still exposes transport metrics */ }
    }
    return { registry, ready, collectBusinessMetrics, httpLatency };
}

function registerHealthMetrics(app, options) {
    const obs = createObservability(options); app.locals.healthMetricsRegistered = true;
    app.use((req, res, next) => { const started = process.hrtime.bigint(); res.on('finish', () => obs.httpLatency.observe({ method: req.method, route: req.route?.path || req.path, status: String(res.statusCode) }, Number(process.hrtime.bigint() - started) / 1e9)); next(); });
    app.get('/health/live', (req, res) => res.json({ live: true }));
    app.get('/health/ready', async (req, res) => { const status = await obs.ready(); res.status(status.ready ? 200 : 503).json(status); });
    app.get('/metrics', async (req, res) => { await obs.collectBusinessMetrics(); res.set('Content-Type', obs.registry.contentType); res.send(await obs.registry.metrics()); });
    return obs;
}
module.exports = { createObservability, registerHealthMetrics };
