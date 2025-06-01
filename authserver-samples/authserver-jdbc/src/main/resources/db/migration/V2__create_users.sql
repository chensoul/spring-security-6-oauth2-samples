CREATE TABLE users
(
    username VARCHAR(200) NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled  BOOLEAN      NOT NULL
);

CREATE TABLE authorities
(
    username  VARCHAR(200) NOT NULL,
    authority VARCHAR(50)  NOT NULL,
    CONSTRAINT fk_authorities_user FOREIGN KEY (username) REFERENCES users (username),
    CONSTRAINT username_authority UNIQUE (username, authority)
);