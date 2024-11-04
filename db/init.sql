CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    input_type VARCHAR(10) NOT NULL, -- "ip", "domain", "url"
    request TEXT NOT NULL,
    response JSONB NOT NULL,
    access_count INT DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_results_request ON scan_results (input_type, request);
CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON scan_results (created_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_access_count ON scan_results (access_count);
