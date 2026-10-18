const { z } = require('zod');
const { API_KEY_ENVIRONMENTS, issueApiKey } = require('./apiKeys');

const ROLES = Object.freeze(['owner', 'admin', 'developer', 'viewer']);
const ROLE_RANK = Object.freeze(Object.fromEntries(ROLES.map((role, index) => [role, index])));
const walletSchema = z.string().trim().min(1).max(255);
const createOrganizationSchema = z.object({
    name: z.string().trim().min(1).max(255),
    slug: z.string().trim().toLowerCase().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(80),
});
const memberSchema = z.object({
    wallet_address: walletSchema,
    role: z.enum(ROLES).default('viewer'),
});
const updateMemberSchema = z.object({ role: z.enum(ROLES) });
const memberApiKeySchema = z.object({
    name: z.string().trim().min(1).max(255),
    environment: z.enum(API_KEY_ENVIRONMENTS),
    wallet_address: walletSchema,
});

const canManage = (actorRole, targetRole) =>
    ROLE_RANK[actorRole] !== undefined && ROLE_RANK[targetRole] !== undefined
    && ROLE_RANK[actorRole] < ROLE_RANK[targetRole];

const actorWallet = (req) => req.apiKey?.member_wallet || req.merchant?.wallet_address;

const fetchOrganization = async (supabase, organizationId, merchantId) => {
    const { data, error } = await supabase
        .from('organizations')
        .select('id, merchant_id, name, slug, created_at')
        .eq('id', organizationId)
        .eq('merchant_id', merchantId)
        .maybeSingle();
    if (error) throw error;
    return data;
};

const fetchMembership = async (supabase, organizationId, wallet) => {
    const { data, error } = await supabase
        .from('organization_members')
        .select('id, organization_id, wallet_address, role, created_at')
        .eq('organization_id', organizationId)
        .eq('wallet_address', wallet)
        .maybeSingle();
    if (error) throw error;
    return data;
};

/**
 * Protects an organization-scoped endpoint. The authenticated API key has a
 * member wallet bound to it (or falls back to the merchant owner's wallet for
 * legacy keys); it is never taken from an untrusted request header.
 */
const requireRole = (getSupabase, minimumRole = 'viewer', resolveOrganizationId = (req) => req.params.organizationId) => async (req, res, next) => {
    if (!ROLES.includes(minimumRole)) throw new Error(`Unknown role: ${minimumRole}`);
    const supabase = getSupabase();
    if (!supabase) return res.status(500).json({ error: 'Supabase client not initialized' });
    try {
        const organizationId = resolveOrganizationId(req);
        const organization = await fetchOrganization(supabase, organizationId, req.merchant.id);
        if (!organization) return res.status(404).json({ error: 'Organization not found' });
        const membership = await fetchMembership(supabase, organizationId, actorWallet(req));
        if (!membership || ROLE_RANK[membership.role] > ROLE_RANK[minimumRole]) {
            return res.status(403).json({ error: 'Insufficient organization role' });
        }
        req.organization = organization;
        req.organizationMember = membership;
        next();
    } catch (error) {
        next(error);
    }
};

function registerOrganizationRoutes(app, getSupabase, authenticateMerchant) {
    app.post('/organizations', authenticateMerchant, async (req, res, next) => {
        const parsed = createOrganizationSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
        const supabase = getSupabase();
        if (!supabase) return res.status(500).json({ error: 'Supabase client not initialized' });
        try {
            const { data: organization, error } = await supabase.from('organizations').insert([{
                merchant_id: req.merchant.id,
                ...parsed.data,
            }]).select('id, merchant_id, name, slug, created_at').single();
            if (error) {
                if (error.code === '23505') return res.status(409).json({ error: 'Organization name or slug already exists' });
                throw error;
            }
            const { error: memberError } = await supabase.from('organization_members').insert([{
                organization_id: organization.id,
                wallet_address: actorWallet(req),
                role: 'owner',
            }]);
            if (memberError) throw memberError;
            res.status(201).json({ organization, member_role: 'owner' });
        } catch (error) { next(error); }
    });

    app.get('/organizations', authenticateMerchant, async (req, res, next) => {
        try {
            const { data, error } = await getSupabase().from('organizations')
                .select('id, merchant_id, name, slug, created_at')
                .eq('merchant_id', req.merchant.id)
                .order('created_at', { ascending: true });
            if (error) throw error;
            res.json({ organizations: data || [] });
        } catch (error) { next(error); }
    });

    app.get('/organizations/:organizationId/members', authenticateMerchant, requireRole(getSupabase, 'viewer'), async (req, res, next) => {
        try {
            const { data, error } = await getSupabase().from('organization_members')
                .select('id, organization_id, wallet_address, role, created_at')
                .eq('organization_id', req.organization.id)
                .order('created_at', { ascending: true });
            if (error) throw error;
            res.json({ members: data || [] });
        } catch (error) { next(error); }
    });

    // An invite is a durable, wallet-addressed membership. No email address or
    // bearer invitation token is stored, eliminating a second credential to leak.
    app.post('/organizations/:organizationId/members', authenticateMerchant, requireRole(getSupabase, 'admin'), async (req, res, next) => {
        const parsed = memberSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
        if (!canManage(req.organizationMember.role, parsed.data.role)) return res.status(403).json({ error: 'Cannot invite a peer or higher role' });
        try {
            const { data, error } = await getSupabase().from('organization_members').insert([{
                organization_id: req.organization.id,
                ...parsed.data,
            }]).select('id, organization_id, wallet_address, role, created_at').single();
            if (error) {
                if (error.code === '23505') return res.status(409).json({ error: 'Wallet is already a member' });
                throw error;
            }
            res.status(201).json({ member: data });
        } catch (error) { next(error); }
    });

    app.patch('/organizations/:organizationId/members/:walletAddress', authenticateMerchant, requireRole(getSupabase, 'admin'), async (req, res, next) => {
        const parsed = updateMemberSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
        try {
            const target = await fetchMembership(getSupabase(), req.organization.id, req.params.walletAddress);
            if (!target) return res.status(404).json({ error: 'Organization member not found' });
            if (!canManage(req.organizationMember.role, target.role) || !canManage(req.organizationMember.role, parsed.data.role)) {
                return res.status(403).json({ error: 'Cannot change a peer or higher role' });
            }
            const { data, error } = await getSupabase().from('organization_members').update(parsed.data)
                .eq('id', target.id).select('id, organization_id, wallet_address, role, created_at').single();
            if (error) throw error;
            res.json({ member: data });
        } catch (error) { next(error); }
    });

    app.delete('/organizations/:organizationId/members/:walletAddress', authenticateMerchant, requireRole(getSupabase, 'admin'), async (req, res, next) => {
        try {
            const target = await fetchMembership(getSupabase(), req.organization.id, req.params.walletAddress);
            if (!target) return res.status(404).json({ error: 'Organization member not found' });
            if (!canManage(req.organizationMember.role, target.role)) return res.status(403).json({ error: 'Cannot remove a peer or higher role' });
            const { error } = await getSupabase().from('organization_members').delete().eq('id', target.id);
            if (error) throw error;
            res.status(204).send();
        } catch (error) { next(error); }
    });

    // Capabilities are explicitly bound to the invited wallet. This keeps role
    // checks meaningful for server-to-server API access as well as the dashboard.
    app.post('/organizations/:organizationId/api-keys', authenticateMerchant, requireRole(getSupabase, 'admin'), async (req, res, next) => {
        const parsed = memberApiKeySchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
        if (parsed.data.environment === 'live' && req.apiKey.environment !== 'live') {
            return res.status(403).json({ error: 'Live API keys can only be created with a live API key' });
        }
        try {
            const member = await fetchMembership(getSupabase(), req.organization.id, parsed.data.wallet_address);
            if (!member) return res.status(404).json({ error: 'Organization member not found' });
            if (!canManage(req.organizationMember.role, member.role) && member.wallet_address !== actorWallet(req)) {
                return res.status(403).json({ error: 'Cannot issue a key for a peer or higher role' });
            }
            const { apiKey, secret, error } = await issueApiKey(getSupabase(), {
                merchantId: req.merchant.id,
                name: parsed.data.name,
                environment: parsed.data.environment,
                organizationMemberWallet: member.wallet_address,
            });
            if (error) throw error;
            res.set('Cache-Control', 'no-store');
            res.status(201).json({ api_key: apiKey, secret });
        } catch (error) { next(error); }
    });
}

module.exports = { ROLES, ROLE_RANK, canManage, requireRole, registerOrganizationRoutes };
