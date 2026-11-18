CREATE TABLE user (id INTEGER PRIMARY KEY, username VARCHAR(80) NOT NULL UNIQUE, password_hash VARCHAR(128) NOT NULL);
CREATE TABLE api_token (
    id INTEGER PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    encrypted_token BLOB NOT NULL,
    status VARCHAR(20) NOT NULL,
    remarks TEXT,
    added_at DATETIME,
    user_id INTEGER NOT NULL REFERENCES user(id)
);
CREATE TABLE domain (
    id INTEGER PRIMARY KEY,
    zone_id VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50),
    fetched_at DATETIME,
    api_token_id INTEGER NOT NULL REFERENCES api_token(id)
);
CREATE TABLE dns_record (
    id INTEGER PRIMARY KEY,
    record_id VARCHAR(100) NOT NULL UNIQUE,
    type VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    content VARCHAR(1000) NOT NULL,
    ttl INTEGER,
    proxied BOOLEAN,
    domain_id INTEGER NOT NULL REFERENCES domain(id)
);
INSERT INTO user VALUES (1, 'legacy', 'unused');
INSERT INTO api_token (id, name, encrypted_token, status, user_id) VALUES
    (10, 'legacy-a', X'1234', 'valid', 1),
    (11, 'legacy-b', X'5678', 'valid', 1);
INSERT INTO domain (id, zone_id, name, api_token_id) VALUES (20, 'example.test', 'example.test', 10);
INSERT INTO dns_record (id, record_id, type, name, content, ttl, domain_id)
    VALUES (30, 'remote-record', 'A', 'www.example.test', '192.0.2.1', 600, 20);
