-- +goose Up
-- +goose StatementBegin

-- Create a shared trigger function to automatically update the updated_at timestamp.
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------
-- Users & Core Auth
-- ---------------------------------

CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    status SMALLINT NOT NULL DEFAULT 0, -- (e.g., 0: Unverified, 1: Active, 2: Banned).
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a unique index on the lowercase version of the email.
-- This enforces uniqueness across all users, including those that are soft-deleted.
CREATE UNIQUE INDEX idx_users_lower_case_email ON users (lower(email)) WHERE deleted_at IS NULL;

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

CREATE TABLE user_credentials (
    user_id BIGINT PRIMARY KEY,
    hashed_password TEXT NOT NULL,
    password_last_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE user_connections (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE,
        
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_user_connections_user_id ON user_connections(user_id);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON user_connections
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

-- ---------------------------------
-- RBAC (Role-Based Access Control)
-- ---------------------------------

CREATE TABLE permissions (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    description TEXT,
    UNIQUE(action, resource)
);

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_permission FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_role FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- ---------------------------------
-- MFA (Multi-Factor Authentication)
-- ---------------------------------

CREATE TABLE mfa_factors (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    type SMALLINT NOT NULL, -- (e.g., 0: unknown, 1: totp, 2: sms, 3: backup_code)
    friendly_name VARCHAR(100),
    secret TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_mfa_factors_user_id ON mfa_factors(user_id);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON mfa_factors
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

CREATE TABLE mfa_backup_codes (
    id BIGINT PRIMARY KEY,
    mfa_factor_id BIGINT NOT NULL,
    hashed_code TEXT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_mfa_factor FOREIGN KEY(mfa_factor_id) REFERENCES mfa_factors(id) ON DELETE CASCADE
);

CREATE INDEX idx_mfa_backup_codes_mfa_factor_id ON mfa_backup_codes(mfa_factor_id);

-- ---------------------------------
-- Seeder -- Secret123!
-- ---------------------------------

INSERT INTO users (id, email, full_name, status) VALUES (1, 'admin@admin.com', 'Admin', 1);

INSERT INTO user_credentials (user_id, hashed_password) 
VALUES (1, '$argon2id$v=19$m=19456,t=2,p=1$1poWFHFX8nhy0ft/dZEgaA$42X7jwLarA/+33BJIfomLqJSeUYXyVJX2tNyAleIivA');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mfa_backup_codes;
DROP TABLE IF EXISTS mfa_factors;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS user_connections;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS trigger_set_timestamp();
-- +goose StatementEnd
