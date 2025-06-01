CREATE TABLE rsa_key_pairs
(
    id          VARCHAR(128) NOT NULL PRIMARY KEY,
    private_key varchar(2048)          NOT NULL,
    public_key  varchar(2048)          NOT NULL,
    created     DATE          NOT NULL
);