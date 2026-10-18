const crypto = require('crypto');

const API_KEY_ENVIRONMENTS = ['live', 'test'];
// orb_<environment>_<32 random bytes as hex>
const API_KEY_PATTERN = /^orb_(live|test)_([0-9a-f]{64})$/;
// Number of secret hex characters kept in the stored prefix, e.g. orb_live_71c2
const PREFIX_SECRET_CHARS = 4;
// last_used_at is only written when it is older than this, so every request is not a DB write
const LAST_USED_WRITE_INTERVAL_MS = Number(process.env.API_KEY_LAST_USED_WRITE_INTERVAL_MS) || 60 * 1000;

const API_KEY_SELECT = 'id, merchant_id, name, key_prefix, environment, organization_member_wallet, last_used_at, revoked_at, merchants(id, name, wallet_address)';

const hashApiKey = (secret) => crypto.createHash('sha256').update(secret).digest('hex');

// Returns { environment, prefix } for a well-formed key, or null
const parseApiKey = (secret) => {
    const match = API_KEY_PATTERN.exec(secret);
    if (!match) return null;
    const [, environment, random] = match;
    return { environment, prefix: `orb_${environment}_${random.slice(0, PREFIX_SECRET_CHARS)}` };
};

// Generates a new key. The secret is returned to the caller exactly once and never stored.
const generateApiKey = (environment) => {
    if (!API_KEY_ENVIRONMENTS.includes(environment)) {
        throw new Error(`environment must be one of: ${API_KEY_ENVIRONMENTS.join(', ')}`);
    }
    const secret = `orb_${environment}_${crypto.randomBytes(32).toString('hex')}`;
    const { prefix } = parseApiKey(secret);
    return { secret, prefix, hash: hashApiKey(secret), environment };
};

// Inserts a key for a merchant. Returns { apiKey, secret }; only the hash is persisted.
const issueApiKey = async (supabase, { merchantId, name, environment, organizationMemberWallet = null }) => {
    const { secret, prefix, hash } = generateApiKey(environment);
    const row = { merchant_id: merchantId, name, key_prefix: prefix, key_hash: hash, environment };
    if (organizationMemberWallet) row.organization_member_wallet = organizationMemberWallet;
    const { data, error } = await supabase
        .from('api_keys')
        .insert([row])
        .select('id, name, key_prefix, environment, organization_member_wallet, created_at, last_used_at, revoked_at')
        .single();
    if (error) return { error };
    return { apiKey: data, secret };
};

const unauthorized = (res, message) => {
    res.set('WWW-Authenticate', 'Bearer realm="orbit"');
    return res.status(401).json({ error: message });
};

// Fire-and-forget, throttled update of last_used_at; failures never block the request
const touchLastUsed = (supabase, keyRow) => {
    const lastUsed = keyRow.last_used_at ? new Date(keyRow.last_used_at).getTime() : 0;
    if (Date.now() - lastUsed < LAST_USED_WRITE_INTERVAL_MS) return;

    const query = supabase
        .from('api_keys')
        .update({ last_used_at: new Date().toISOString() })
        .eq('id', keyRow.id);
    Promise.resolve(query)
        .then((result) => {
            if (result?.error) console.error("Error updating API key last_used_at:", result.error);
        })
        .catch((err) => console.error("Error updating API key last_used_at:", err));
};

/**
 * Authenticates `Authorization: Bearer orb_...` requests.
 *
 * The token is hashed and looked up by its SHA-256 digest; revoked keys, keys whose
 * stored prefix/environment disagree with the token, and keys whose merchant no longer
 * exists are all rejected with the same 401. On success binds:
 *   req.merchant = { id, name, wallet_address }
 *   req.apiKey   = { id, name, prefix, environment }
 */
const requireApiKey = (getSupabase) => async (req, res, next) => {
    const match = /^Bearer\s+(\S+)\s*$/i.exec(req.get('Authorization') ?? '');
    if (!match) return unauthorized(res, "Missing API key: send Authorization: Bearer orb_...");

    const secret = match[1];
    const parsed = parseApiKey(secret);
    if (!parsed) return unauthorized(res, "Malformed API key");

    const supabase = getSupabase();
    if (!supabase) return res.status(500).json({ error: "Supabase client not initialized" });

    try {
        const { data: keyRow, error } = await supabase
            .from('api_keys')
            .select(API_KEY_SELECT)
            .eq('key_hash', hashApiKey(secret))
            .maybeSingle();
        if (error) throw error;

        const isActive = keyRow
            && !keyRow.revoked_at
            && keyRow.key_prefix === parsed.prefix
            && keyRow.environment === parsed.environment
            && keyRow.merchants;
        if (!isActive) return unauthorized(res, "Invalid or revoked API key");

        req.merchant = keyRow.merchants;
        req.apiKey = {
            id: keyRow.id,
            name: keyRow.name,
            prefix: keyRow.key_prefix,
            environment: keyRow.environment,
            member_wallet: keyRow.organization_member_wallet || keyRow.merchants.wallet_address,
        };
        touchLastUsed(supabase, keyRow);
        next();
    } catch (err) {
        console.error("Error authenticating API key:", err);
        res.status(500).json({ error: "Failed to authenticate API key" });
    }
};

module.exports = {
    API_KEY_ENVIRONMENTS,
    generateApiKey,
    hashApiKey,
    parseApiKey,
    issueApiKey,
    requireApiKey,
};
