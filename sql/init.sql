-- PADDOCK initial Governance schema (PostgreSQL).
-- Target: database `paddock_test`; creates schema `raw` if absent, then creates
-- all tables explicitly as `raw.<table>`.
-- This file does NOT create/drop databases, roles, or credentials.
-- Apply only to the dedicated PADDOCK test DB, never a production/llm-memory DB.
-- No application tables are dropped by this script. For a clean rebuild, drop the
-- disposable PADDOCK database itself using an explicitly reviewed operator action.
--
-- Run: scripts/init_test_db.sh --apply (requires PADDOCK_DB_URL)
-- DSN must be injected by the operator; never store or print its value.

BEGIN;
DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing to initialize unexpected database %, expected paddock_test', current_database();
    END IF;
END
$$;
CREATE SCHEMA IF NOT EXISTS raw;

CREATE TABLE raw.policy_bundles (
    bundle_digest       char(64) PRIMARY KEY
                        CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
    canonical_bytes     bytea NOT NULL,
    schema_version      text NOT NULL CHECK (schema_version <> ''),
    signer_key_id       text NOT NULL CHECK (signer_key_id <> ''),
    signature           bytea NOT NULL CHECK (octet_length(signature) > 0),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE raw.policy_scopes (
    scope_id                    text PRIMARY KEY CHECK (scope_id <> '' AND scope_id = btrim(scope_id)),
    activation_epoch            bigint NOT NULL DEFAULT 0 CHECK (activation_epoch >= 0),
    baseline_bundle_digest      char(64) REFERENCES raw.policy_bundles(bundle_digest),
    mode                        text NOT NULL DEFAULT 'ACTIVE'
                                CHECK (mode IN ('ACTIVE', 'FROZEN', 'SAFE_STOPPED')),
    live_rollout_id             text,
    updated_at                  timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((mode = 'SAFE_STOPPED') OR baseline_bundle_digest IS NOT NULL)
);

CREATE TABLE raw.roots (
    root_id                 text PRIMARY KEY CHECK (root_id <> '' AND root_id = btrim(root_id)),
    scope_id                text NOT NULL REFERENCES raw.policy_scopes(scope_id),
    authorization_epoch     bigint NOT NULL DEFAULT 0 CHECK (authorization_epoch >= 0),
    effective_bundle_digest char(64) REFERENCES raw.policy_bundles(bundle_digest),
    safe_baseline           boolean NOT NULL DEFAULT false,
    updated_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (root_id, scope_id),
    CHECK (safe_baseline OR effective_bundle_digest IS NOT NULL),
    CHECK (NOT safe_baseline OR effective_bundle_digest IS NULL)
);

CREATE TABLE raw.policy_rollouts (
    rollout_id                  text PRIMARY KEY CHECK (rollout_id <> '' AND rollout_id = btrim(rollout_id)),
    scope_id                    text NOT NULL REFERENCES raw.policy_scopes(scope_id),
    state                       text NOT NULL CHECK (state IN
                                ('SHADOW', 'CANARY', 'MONITORING', 'COMPLETED',
                                 'ROLLING_BACK', 'ROLLED_BACK', 'SAFE_STOPPED')),
    target_root_id              text,
    base_activation_epoch       bigint NOT NULL CHECK (base_activation_epoch >= 0),
    last_activation_epoch       bigint NOT NULL CHECK (last_activation_epoch >= base_activation_epoch),
    base_security_epoch         bigint NOT NULL CHECK (base_security_epoch >= 0),
    rollback_from               text CHECK (rollback_from IS NULL OR rollback_from IN ('CANARY', 'MONITORING')),
    created_at                  timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                  timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (rollout_id, scope_id),
    FOREIGN KEY (target_root_id, scope_id) REFERENCES raw.roots(root_id, scope_id),
    CHECK ((state = 'ROLLING_BACK') = (rollback_from IS NOT NULL))
);

ALTER TABLE raw.policy_scopes
    ADD CONSTRAINT policy_scopes_live_rollout_scope_fk
    FOREIGN KEY (live_rollout_id, scope_id)
    REFERENCES raw.policy_rollouts(rollout_id, scope_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE raw.rollout_targets (
    rollout_id              text NOT NULL,
    scope_id                text NOT NULL,
    root_id                 text NOT NULL,
    baseline_bundle_digest  char(64) REFERENCES raw.policy_bundles(bundle_digest),
    candidate_bundle_digest char(64) NOT NULL REFERENCES raw.policy_bundles(bundle_digest),
    base_root_epoch         bigint NOT NULL CHECK (base_root_epoch >= 0),
    updated_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (rollout_id, root_id),
    FOREIGN KEY (rollout_id, scope_id) REFERENCES raw.policy_rollouts(rollout_id, scope_id),
    FOREIGN KEY (root_id, scope_id) REFERENCES raw.roots(root_id, scope_id)
);

CREATE TABLE raw.governance_approvals (
    approval_id         text PRIMARY KEY CHECK (approval_id <> ''),
    scope_id            text NOT NULL REFERENCES raw.policy_scopes(scope_id),
    subject_digest      char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
    signer_key_id       text NOT NULL CHECK (signer_key_id <> ''),
    signed_payload      bytea NOT NULL CHECK (octet_length(signed_payload) > 0),
    signature           bytea NOT NULL CHECK (octet_length(signature) > 0),
    approved_at         timestamptz NOT NULL,
    expires_at          timestamptz,
    CHECK (expires_at IS NULL OR expires_at > approved_at)
);

CREATE TABLE raw.command_receipts (
    command_id          text PRIMARY KEY CHECK (command_id <> ''),
    request_digest      char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    status              text NOT NULL CHECK (status IN ('IN_PROGRESS', 'SUCCEEDED', 'REJECTED')),
    response_bytes      bytea,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at        timestamptz,
    CHECK ((status = 'IN_PROGRESS') = (completed_at IS NULL)),
    CHECK (status = 'IN_PROGRESS' OR response_bytes IS NOT NULL)
);

CREATE TABLE raw.domain_events (
    event_id            text PRIMARY KEY CHECK (event_id <> ''),
    aggregate_kind      text NOT NULL CHECK (aggregate_kind <> ''),
    aggregate_id        text NOT NULL CHECK (aggregate_id <> ''),
    aggregate_version   bigint NOT NULL CHECK (aggregate_version > 0),
    event_type          text NOT NULL CHECK (event_type <> ''),
    schema_version      text NOT NULL CONSTRAINT domain_events_schema_version_nonempty_ck CHECK (schema_version <> ''),
    payload             bytea NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (aggregate_kind, aggregate_id, aggregate_version)
);

CREATE TABLE raw.event_outbox (
    event_id            text PRIMARY KEY REFERENCES raw.domain_events(event_id),
    available_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at        timestamptz,
    attempt_count       integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error          text,
    claim_token         uuid,
    lease_expires_at    timestamptz,
    dead_lettered_at    timestamptz,
    redrive_count       integer NOT NULL DEFAULT 0 CONSTRAINT event_outbox_redrive_count_ck CHECK (redrive_count BETWEEN 0 AND 1),
    CONSTRAINT event_outbox_claim_pair_ck CHECK ((claim_token IS NULL) = (lease_expires_at IS NULL)),
    CONSTRAINT event_outbox_dead_letter_unclaimed_ck CHECK (dead_lettered_at IS NULL OR (claim_token IS NULL AND lease_expires_at IS NULL)),
    CONSTRAINT event_outbox_published_not_dead_lettered_ck CHECK (published_at IS NULL OR dead_lettered_at IS NULL)
);

CREATE INDEX event_outbox_claimable_idx
    ON raw.event_outbox (available_at, event_id)
    WHERE published_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX event_outbox_redrive_idx
    ON raw.event_outbox (dead_lettered_at, event_id)
    WHERE published_at IS NULL AND dead_lettered_at IS NOT NULL AND redrive_count = 0;

CREATE TABLE raw.event_inbox (
    consumer_id         text NOT NULL CHECK (consumer_id <> ''),
    event_id            text NOT NULL CHECK (event_id <> ''),
    received_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    processed_at        timestamptz,
    PRIMARY KEY (consumer_id, event_id)
);

CREATE TABLE raw.security_generation (
    singleton_id        boolean PRIMARY KEY DEFAULT true CHECK (singleton_id),
    security_epoch      bigint NOT NULL DEFAULT 0 CHECK (security_epoch >= 0),
    updated_at          timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO raw.security_generation (singleton_id, security_epoch)
VALUES (true, 0)
ON CONFLICT (singleton_id) DO NOTHING;

COMMIT;
