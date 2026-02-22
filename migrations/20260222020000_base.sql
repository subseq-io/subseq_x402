CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE SCHEMA IF NOT EXISTS x402;

CREATE TABLE IF NOT EXISTS x402.facilitator_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    verify_url TEXT NOT NULL,
    settle_url TEXT NOT NULL,
    supported_url TEXT NOT NULL,
    default_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    supported_cache_ttl_secs INTEGER NOT NULL DEFAULT 600,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS x402.route_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    method TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    mode TEXT NOT NULL,
    channels JSONB NOT NULL DEFAULT '[]'::jsonb,
    facilitator_profile_id UUID REFERENCES x402.facilitator_profiles(id) ON DELETE SET NULL,
    x402_accepts JSONB NOT NULL DEFAULT '[]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(method, path_pattern)
);

CREATE INDEX IF NOT EXISTS idx_x402_route_policies_method_active
    ON x402.route_policies(method, active);

CREATE TABLE IF NOT EXISTS x402.payment_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT NOT NULL,
    route_policy_id UUID REFERENCES x402.route_policies(id) ON DELETE SET NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    channel TEXT NOT NULL,
    result TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    payer TEXT,
    api_key_id UUID,
    api_key_name TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_x402_payment_audit_created_at
    ON x402.payment_audit(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_x402_payment_audit_request_id
    ON x402.payment_audit(request_id);

CREATE INDEX IF NOT EXISTS idx_x402_payment_audit_channel_result
    ON x402.payment_audit(channel, result);
