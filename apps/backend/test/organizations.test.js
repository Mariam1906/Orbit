import { describe, expect, it, vi } from 'vitest';
import { canManage, requireRole } from '../organizations.js';

const merchant = { id: 'merchant-1', wallet_address: 'GOWNER' };

function response() {
  return { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };
}

function membershipSupabase({ organization = { id: 'org-1', merchant_id: merchant.id }, membership = { id: 'member-1', role: 'admin' } } = {}) {
  return {
    from: vi.fn((table) => {
      const query = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn(async () => ({ data: table === 'organizations' ? organization : membership, error: null })),
      };
      return query;
    }),
  };
}

describe('organization RBAC', () => {
  it('orders roles from owner through viewer', () => {
    expect(canManage('owner', 'admin')).toBe(true);
    expect(canManage('admin', 'developer')).toBe(true);
    expect(canManage('developer', 'admin')).toBe(false);
    expect(canManage('viewer', 'viewer')).toBe(false);
  });

  it('allows a matching organization member with the required role', async () => {
    const next = vi.fn();
    const middleware = requireRole(() => membershipSupabase(), 'developer');
    await middleware({ params: { organizationId: 'org-1' }, merchant, apiKey: { member_wallet: 'GADMIN' } }, response(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('denies a role below the required permission', async () => {
    const res = response();
    const middleware = requireRole(() => membershipSupabase({ membership: { id: 'member-1', role: 'viewer' } }), 'developer');
    await middleware({ params: { organizationId: 'org-1' }, merchant, apiKey: { member_wallet: 'GVIEWER' } }, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('does not reveal an organization from another merchant', async () => {
    const res = response();
    const middleware = requireRole(() => membershipSupabase({ organization: null }), 'viewer');
    await middleware({ params: { organizationId: 'other-org' }, merchant, apiKey: { member_wallet: 'GOWNER' } }, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(404);
  });
});
