CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(150) NOT NULL
);


CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    input_type VARCHAR(10) NOT NULL, -- "ip", "domain", "url"
    request TEXT NOT NULL,
    response JSONB NOT NULL,
    access_count INT DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    UNIQUE (input_type, request)
);

CREATE INDEX IF NOT EXISTS idx_scan_results_request ON scan_results (input_type, request);
CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON scan_results (created_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_access_count ON scan_results (access_count);

CREATE TABLE IF NOT EXISTS user_scan_stats (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    input_type VARCHAR(10) NOT NULL,
    request TEXT NOT NULL,
    zone VARCHAR(10) NOT NULL, -- "Red", "Green", etc.
    access_count INT DEFAULT 0,
    last_accessed TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, input_type, request)
);