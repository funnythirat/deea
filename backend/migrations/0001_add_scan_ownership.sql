BEGIN;

CREATE TABLE IF NOT EXISTS virus_scans (
    id VARCHAR(36) PRIMARY KEY,
    token_hash VARCHAR(64),
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    size_bytes INTEGER NOT NULL,
    mode VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    result JSON,
    error_code VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

ALTER TABLE virus_scans
    ADD COLUMN IF NOT EXISTS owner_uid VARCHAR(128);

ALTER TABLE virus_scans
    ALTER COLUMN token_hash DROP NOT NULL;

CREATE INDEX IF NOT EXISTS ix_virus_scans_status
    ON virus_scans (status);

CREATE INDEX IF NOT EXISTS ix_virus_scans_owner_uid
    ON virus_scans (owner_uid);

COMMIT;
