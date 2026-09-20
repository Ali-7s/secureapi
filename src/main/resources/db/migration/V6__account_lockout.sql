CREATE TABLE IF NOT EXISTS account_lockouts (
                                     id SERIAL PRIMARY KEY,
                                     principal VARCHAR(255) NOT NULL UNIQUE,
                                     locked_until TIMESTAMPTZ NOT NULL,
                                     created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);