-- One psql session owns shape selection, relation locks and the count snapshot.
-- The caller uses -X -q -A -t -v ON_ERROR_STOP=1 so only the final fact is output.
-- The final SELECT takes its statement snapshot after every count table is
-- locked, rather than reusing a snapshot taken by the initial presence probe.
BEGIN READ ONLY ISOLATION LEVEL READ COMMITTED;
LOCK TABLE controller_recovery_roots, controller_registry_slots,
    __diesel_schema_migrations, oauth_clients, recovery_invalidations,
    tenants, user_totp_credentials, users IN ACCESS SHARE MODE;

-- This probe chooses which relations to lock; it does not accept a schema.
-- A concurrent drop before LOCK fails closed. Locks remain held through COMMIT.
SELECT to_regclass('oauth_tokens') IS NOT NULL AS lock_legacy
\gset
\if :lock_legacy
LOCK TABLE oauth_tokens IN ACCESS SHARE MODE;
\else
LOCK TABLE oauth_refresh_contracts, oauth_refresh_families,
    oauth_refresh_spent_tokens IN ACCESS SHARE MODE;
\endif

-- This is the single authoritative shape decision, after the selected locks.
WITH shape AS (
    SELECT
        EXISTS (SELECT 1 FROM __diesel_schema_migrations
                WHERE version = '20260926000100') AS minimal_recorded,
        (SELECT MAX(version)::text FROM __diesel_schema_migrations) AS migration_head,
        to_regclass('oauth_tokens') AS legacy,
        to_regclass('oauth_refresh_contracts') AS contracts,
        to_regclass('oauth_refresh_families') AS families,
        to_regclass('oauth_refresh_spent_tokens') AS spent
)
SELECT
    NOT minimal_recorded AND COALESCE(migration_head < '20260926000100', FALSE)
        AND EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid = legacy AND relkind IN ('r', 'p'))
        AND contracts IS NULL AND families IS NULL AND spent IS NULL AS legacy_shape,
    minimal_recorded AND legacy IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM unnest(ARRAY[contracts, families, spent]) AS required(oid)
            LEFT JOIN pg_catalog.pg_class AS relation ON relation.oid = required.oid
            WHERE relation.oid IS NULL OR relation.relkind NOT IN ('r', 'p')
        ) AS refresh_shape
FROM shape
\gset

\if :legacy_shape
-- Preserve every byte of the legacy fact: labels, order, separators and counts.
SELECT concat_ws('|',
    'controller_recovery_roots=' || (SELECT COUNT(*) FROM controller_recovery_roots),
    'controller_registry_slots=' || (SELECT COUNT(*) FROM controller_registry_slots),
    'migration_head=' || COALESCE((SELECT MAX(version)::text FROM __diesel_schema_migrations), ''),
    'oauth_clients=' || (SELECT COUNT(*) FROM oauth_clients),
    'oauth_tokens=' || (SELECT COUNT(*) FROM oauth_tokens),
    'recovery_invalidations=' || (SELECT COUNT(*) FROM recovery_invalidations),
    'tenants=' || (SELECT COUNT(*) FROM tenants),
    'user_totp_credentials=' || (SELECT COUNT(*) FROM user_totp_credentials),
    'users=' || (SELECT COUNT(*) FROM users));
\elif :refresh_shape
SELECT concat_ws('|',
    'controller_recovery_roots=' || (SELECT COUNT(*) FROM controller_recovery_roots),
    'controller_registry_slots=' || (SELECT COUNT(*) FROM controller_registry_slots),
    'migration_head=' || COALESCE((SELECT MAX(version)::text FROM __diesel_schema_migrations), ''),
    'oauth_clients=' || (SELECT COUNT(*) FROM oauth_clients),
    'oauth_refresh_contracts=' || (SELECT COUNT(*) FROM oauth_refresh_contracts),
    'oauth_refresh_families=' || (SELECT COUNT(*) FROM oauth_refresh_families),
    'oauth_refresh_spent_tokens=' || (SELECT COUNT(*) FROM oauth_refresh_spent_tokens),
    'recovery_invalidations=' || (SELECT COUNT(*) FROM recovery_invalidations),
    'tenants=' || (SELECT COUNT(*) FROM tenants),
    'user_totp_credentials=' || (SELECT COUNT(*) FROM user_totp_credentials),
    'users=' || (SELECT COUNT(*) FROM users));
\else
DO $$ BEGIN
    RAISE EXCEPTION 'unsupported database sentinel schema: migration ledger and token relations disagree';
END $$;
\endif
COMMIT;
