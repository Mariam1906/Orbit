const { rpc, scValToNative } = require('@stellar/stellar-sdk');

const jsonValue = (value) => JSON.parse(JSON.stringify(value, (_, item) =>
    typeof item === 'bigint' ? item.toString() : item));

function serializeEvent(event) {
    const topics = event.topic.map(scValToNative);
    const name = String(topics[0]);
    return {
        id: event.id,
        ledger_sequence: event.ledger,
        transaction_hash: event.txHash,
        contract_id: event.contractId.contractId(),
        event_name: name,
        merchant_address: ['batch_disbursed', 'plan_registered', 'plan_deactivated'].includes(name) ? topics[1] : topics[2] || null,
        topics: jsonValue(topics),
        value: jsonValue(scValToNative(event.value)),
        closed_at: event.ledgerClosedAt,
    };
}

function createLedgerIndexer({ supabase, server, contractId, startLedger, batchSize = 100,
    pageSize = 1000, logger = console }) {
    if (!Number.isSafeInteger(startLedger) || startLedger < 1) {
        throw new Error('INDEXER_START_LEDGER must be a positive ledger sequence');
    }
    if (!contractId) throw new Error('ORBIT_CONTRACT_ID is required for event indexing');
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('INDEXER_BATCH_SIZE must be between 1 and 1000');
    const streamId = `${process.env.STELLAR_NETWORK_PASSPHRASE || 'testnet'}:${contractId}`;
    let running = false;
    let lastError = null;

    async function checkpoint() {
        const { data, error } = await supabase.from('ledger_checkpoints')
            .select('last_processed_ledger_sequence').eq('stream_id', streamId).maybeSingle();
        if (error) throw error;
        return data?.last_processed_ledger_sequence ?? startLedger - 1;
    }

    async function health() {
        try {
            const [saved, latest] = await Promise.all([checkpoint(), server.getLatestLedger()]);
            const lag = Math.max(0, latest.sequence - saved);
            if (lag > 20) logger.error({ severity: 'critical', event: 'ledger_indexer_lag',
                ledger_lag: lag, last_processed_ledger_sequence: saved, latest_ledger: latest.sequence });
            return { ready: lag <= 20 && saved <= latest.sequence && !lastError,
                last_processed_ledger_sequence: saved, latest_ledger: latest.sequence,
                ledger_lag: lag, warning: lastError || (lag > 20 ? 'Indexer is more than 20 ledgers behind' :
                    saved > latest.sequence ? 'RPC is behind the saved checkpoint' : null) };
        } catch (error) {
            return { ready: false, ledger_lag: null, warning: error.message };
        }
    }

    async function ingest() {
        if (running) return;
        running = true;
        try {
            const saved = await checkpoint();
            const latest = await server.getLatestLedger();
            if (saved >= latest.sequence) { lastError = null; return; }
            const endLedger = Math.min(saved + batchSize, latest.sequence) + 1;
            const filters = [{ type: 'contract', contractIds: [contractId] }];
            let request = { startLedger: saved + 1, endLedger, filters, limit: pageSize };
            const events = new Map();
            let previousCursor;
            for (let page = 0; ; page += 1) {
                if (page >= 100) throw new Error('Event batch exceeds pagination limit; reduce INDEXER_BATCH_SIZE');
                const response = await server.getEvents(request);
                if (response.oldestLedger > saved + 1) throw new Error('Saved checkpoint is outside RPC retention; archival backfill required');
                if (response.latestLedger < endLedger - 1) throw new Error('RPC has not reached the requested batch boundary');
                for (const event of response.events) {
                    if (event.inSuccessfulContractCall !== false && event.ledger >= saved + 1 && event.ledger < endLedger) events.set(event.id, serializeEvent(event));
                }
                if (response.events.some((event) => event.ledger >= endLedger) || response.events.length < pageSize) break;
                if (!response.cursor || response.cursor === previousCursor) throw new Error('RPC event cursor did not advance');
                previousCursor = response.cursor;
                // RPC cursor pagination cannot include startLedger/endLedger.
                request = { cursor: response.cursor, filters, limit: pageSize };
            }
            // One PostgreSQL transaction stores every event and advances the checkpoint.
            // CAS prevents a stale worker from overwriting another worker's progress.
            const { error } = await supabase.rpc('commit_ledger_batch', {
                p_stream_id: streamId, p_expected_sequence: saved,
                p_last_sequence: endLedger - 1, p_events: [...events.values()],
            });
            if (error) throw error;
            lastError = null;
        } catch (error) {
            lastError = error.message;
            logger.error({ severity: 'critical', event: 'ledger_ingestion_failed', message: error.message });
            throw error;
        } finally { running = false; }
    }

    function start(intervalMs = 5000) {
        const tick = async () => {
            try { await ingest(); } catch { /* surfaced in readiness and structured logs */ }
            await health();
        };
        void tick();
        const timer = setInterval(tick, intervalMs);
        timer.unref();
        return { stop: () => clearInterval(timer) };
    }
    return { ingest, health, start, streamId };
}

function registerIndexerRoutes(app) {
    if (app.locals.healthMetricsRegistered) return;
    app.get('/health/ready', async (req, res) => {
        if (!app.locals.ledgerIndexer) return res.status(503).json({ ready: false, warning: 'Ledger indexer is not configured' });
        const status = await app.locals.ledgerIndexer.health();
        res.status(status.ready ? 200 : 503).json(status);
    });
}

function configuredIndexer(supabase) {
    return createLedgerIndexer({ supabase,
        server: new rpc.Server(process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org'),
        contractId: process.env.ORBIT_CONTRACT_ID,
        startLedger: Number(process.env.INDEXER_START_LEDGER),
        batchSize: Number(process.env.INDEXER_BATCH_SIZE) || 100 });
}

module.exports = { createLedgerIndexer, registerIndexerRoutes, configuredIndexer };
