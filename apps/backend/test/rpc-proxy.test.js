import { describe, expect, it, vi } from 'vitest';
import { CircuitBreaker, createRpcProxy } from '../rpc-proxy.js';

describe('Soroban RPC proxy', () => {
  it('allows only the explicitly supported read methods', async () => {
    const proxy = createRpcProxy({ urls: ['https://rpc.example'], fetchImpl: vi.fn() });
    await expect(proxy.call({ method: 'sendTransaction', params: [] })).rejects.toMatchObject({ statusCode: 400 });
  });
  it('caches immutable RPC responses while preserving each caller id', async () => {
    let time = 1;
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: { entries: [] } }) });
    const proxy = createRpcProxy({ urls: ['https://rpc.example'], fetchImpl, now: () => time });
    expect((await proxy.call({ method: 'getLedgerEntries', params: ['x'], id: 1 })).id).toBe(1);
    expect((await proxy.call({ method: 'getLedgerEntries', params: ['x'], id: 2 })).id).toBe(2);
    expect(fetchImpl).toHaveBeenCalledOnce();
    time += 31_000;
    await proxy.call({ method: 'getLedgerEntries', params: ['x'], id: 3 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
  it('opens failed endpoints and fails over to the next configured RPC', async () => {
    const fetchImpl = vi.fn().mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce({ ok: true, json: async () => ({ result: { sequence: 1 } }) });
    const proxy = createRpcProxy({ urls: ['https://bad.example', 'https://good.example'], fetchImpl, breaker: new CircuitBreaker({ failureThreshold: 1 }) });
    expect((await proxy.call({ method: 'getLatestLedger', params: [] })).result.sequence).toBe(1);
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual(['https://bad.example', 'https://good.example']);
  });
});
