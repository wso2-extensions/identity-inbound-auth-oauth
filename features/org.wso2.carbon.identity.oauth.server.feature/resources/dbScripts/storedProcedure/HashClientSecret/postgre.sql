/* =======================================================================
   Hash plain-text consumer_secret in idn_oauth_consumer_apps (PostgreSQL 14+)
   Target format (matches client-secret-only hash processor):
     {"hash":"<sha256-hex-lowercase>","algorithm":"SHA-256"}

   USAGE:
     1. Run this file once to (re)create the procedure:
           psql -h <host> -U <user> -d <db> -v ON_ERROR_STOP=1 -f postgre.sql
        (or, from an already-open psql session: \i postgre.sql)
     2. Execute it with your schema:
            CALL hash_consumer_secrets( schemaName, batchSize);
          Example: CALL hash_consumer_secrets('public', 500);
     3. Optionally drop it after the migration:
           DROP PROCEDURE hash_consumer_secrets(TEXT, INT);
======================================================================= */

CREATE OR REPLACE PROCEDURE hash_consumer_secrets(
    schema_name TEXT DEFAULT 'public',
    batch_size  INT  DEFAULT 500
)
LANGUAGE plpgsql
AS $$
DECLARE
    apps_tbl      TEXT := format('%I.%I', schema_name, 'idn_oauth_consumer_apps');
    rows_affected INT  := 1;
    total_hashed  BIGINT := 0;
    bad_rows      INT;
BEGIN
    IF batch_size IS NULL OR batch_size <= 0 OR batch_size > 10000 THEN
        RAISE EXCEPTION 'batch_size must be between 1 and 10000';
    END IF;

    IF to_regclass(apps_tbl) IS NULL THEN
        RAISE EXCEPTION 'idn_oauth_consumer_apps does not exist in schema %', schema_name;
    END IF;

    -----------------------------------------------------------------
    -- 1. Batched UPDATE. Per-batch transaction.
    -----------------------------------------------------------------
    WHILE rows_affected > 0 LOOP
        EXECUTE format($f$
            WITH candidates AS (
                SELECT id
                FROM %s
                WHERE consumer_secret IS NOT NULL
                  AND consumer_secret NOT LIKE '{"hash":%%'
                  AND consumer_secret NOT LIKE '{"algorithm":%%'
                ORDER BY id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
            )
            UPDATE %s t
            SET consumer_secret = '{"hash":"'
                || lower(encode(sha256(convert_to(t.consumer_secret, 'UTF8')), 'hex'))
                || '","algorithm":"SHA-256"}'
            FROM candidates c
            WHERE t.id = c.id
        $f$, apps_tbl, batch_size, apps_tbl);

        GET DIAGNOSTICS rows_affected = ROW_COUNT;
        total_hashed := total_hashed + rows_affected;

        COMMIT;
    END LOOP;

    RAISE NOTICE 'Rows hashed: %', total_hashed;

    -----------------------------------------------------------------
    -- 2. Verification. every non-null secret must be JSON-wrapped with
    -- a 64-char lowercase hex digest inside.
    -----------------------------------------------------------------
    EXECUTE format($f$
        SELECT COUNT(*) FROM %s
        WHERE consumer_secret IS NOT NULL
          AND consumer_secret !~ '^\{"hash":"[0-9a-f]{64}","algorithm":"SHA-256"\}$'
          AND consumer_secret !~ '^\{"algorithm":"SHA-256","hash":"[0-9a-f]{64}"\}$'
    $f$, apps_tbl) INTO bad_rows;

    IF bad_rows > 0 THEN
        RAISE EXCEPTION 'Verification failed: some consumer_secret values are not in the expected hashed JSON format.';
    ELSE
        RAISE NOTICE 'Verification passed.';
    END IF;
END;
$$;