CREATE DATABASE SecurePasswords;
USE SecurePasswords;

CREATE TABLE Logins (
    username VARCHAR(50) PRIMARY KEY,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL
);