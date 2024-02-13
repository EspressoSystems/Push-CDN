-- Add migration script here
CREATE TABLE IF NOT EXISTS brokers (
    identifier TEXT PRIMARY KEY NOT NULL,
    num_connections INTEGER NOT NULL,
    expiry DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS permits (
    identifier TEXT NOT NULL,
    permit INTEGER NOT NULL PRIMARY KEY,
    user_pubkey BLOB NOT NULL,
    expiry DATETIME NOT NULL
)