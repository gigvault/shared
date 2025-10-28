-- Migration: Create encrypted_keys table
-- This table stores encrypted private keys using envelope encryption

CREATE TABLE IF NOT EXISTS encrypted_keys (
    key_id VARCHAR(255) PRIMARY KEY,
    encrypted_dek BYTEA NOT NULL,          -- Data Encryption Key (encrypted with HSM master key)
    encrypted_key BYTEA NOT NULL,          -- Private key (encrypted with DEK)
    nonce BYTEA NOT NULL,                  -- Nonce for GCM encryption
    algorithm VARCHAR(50) NOT NULL,        -- e.g., "ECDSA-P256"
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    use_count BIGINT DEFAULT 0,
    
    -- Metadata for auditing
    created_by VARCHAR(255),
    purpose VARCHAR(255),                  -- e.g., "root-ca", "intermediate-ca"
    
    -- Constraints
    CONSTRAINT encrypted_key_length CHECK (octet_length(encrypted_key) > 0),
    CONSTRAINT encrypted_dek_length CHECK (octet_length(encrypted_dek) > 0),
    CONSTRAINT nonce_length CHECK (octet_length(nonce) = 12)  -- GCM nonce size
);

-- Indexes
CREATE INDEX idx_encrypted_keys_created_at ON encrypted_keys(created_at DESC);
CREATE INDEX idx_encrypted_keys_algorithm ON encrypted_keys(algorithm);
CREATE INDEX idx_encrypted_keys_purpose ON encrypted_keys(purpose);

-- Audit trigger (optional - log all key access)
CREATE TABLE IF NOT EXISTS encrypted_keys_audit (
    id SERIAL PRIMARY KEY,
    key_id VARCHAR(255) NOT NULL,
    operation VARCHAR(50) NOT NULL,       -- 'access', 'rotate', 'delete'
    performed_by VARCHAR(255),
    performed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX idx_encrypted_keys_audit_key_id ON encrypted_keys_audit(key_id);
CREATE INDEX idx_encrypted_keys_audit_performed_at ON encrypted_keys_audit(performed_at DESC);

-- Function to update rotated_at
CREATE OR REPLACE FUNCTION update_rotated_at()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.encrypted_dek != OLD.encrypted_dek OR NEW.encrypted_key != OLD.encrypted_key THEN
        NEW.rotated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_rotated_at
    BEFORE UPDATE ON encrypted_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_rotated_at();

-- Comments
COMMENT ON TABLE encrypted_keys IS 'Stores encrypted private keys using envelope encryption. Master key is in HSM.';
COMMENT ON COLUMN encrypted_keys.encrypted_dek IS 'Data Encryption Key encrypted with HSM master key';
COMMENT ON COLUMN encrypted_keys.encrypted_key IS 'Private key encrypted with DEK';
COMMENT ON COLUMN encrypted_keys.nonce IS 'GCM nonce (12 bytes)';

