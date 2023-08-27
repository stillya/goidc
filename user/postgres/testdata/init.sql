CREATE TABLE IF NOT EXISTS users(
    user_id    VARCHAR(255) PRIMARY KEY,
    username   VARCHAR(255) UNIQUE NOT NULL,
    disabled   boolean DEFAULT FALSE,
    attributes JSONB
);