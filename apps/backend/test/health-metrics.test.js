import { describe, expect, it } from 'vitest';
import { createObservability } from '../health-metrics.js';
describe('health observability', () => {
  it('reports ready only when Supabase and Soroban RPC are both healthy', async () => {
    const db = { from: () => ({ select: () => ({ limit: async () => ({ error: null }) }) }) };
    const ok = createObservability({ getSupabase: () => db, getSorobanServer: () => ({ getLatestLedger: async () => ({ sequence: 1 }) }) });
    expect((await ok.ready()).ready).toBe(true);
    const down = createObservability({ getSupabase: () => db, getSorobanServer: () => ({ getLatestLedger: async () => { throw new Error('down'); } }) });
    expect((await down.ready()).ready).toBe(false);
  });
});
