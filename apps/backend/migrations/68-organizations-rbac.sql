-- Multi-tenant organizations and wallet-bound RBAC (#68).
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL UNIQUE REFERENCES merchants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(80) NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    wallet_address VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, wallet_address)
);
CREATE INDEX IF NOT EXISTS organization_members_org_role_idx ON organization_members (organization_id, role);

-- API keys are capabilities issued to a particular organization member. Legacy
-- keys remain bound to the merchant owner wallet until they are rotated.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS organization_member_wallet VARCHAR(255);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE organizations, organization_members FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, organization_members TO service_role;
