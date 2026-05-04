# Hash Consumer Secrets — MSSQL

Migrates plain-text `CONSUMER_SECRET` values in `IDN_OAUTH_CONSUMER_APPS` to SHA-256 hashes of the form:

```
{"hash":"<sha256-hex-lowercase>","algorithm":"SHA-256"}
```

---

## Option A — Without backup (default)

Use this when a full database snapshot has already been taken. No backup table is created.

**Step 1 — Create the procedure**

```sql
:r HashConsumerSecrets.sql
```

**Step 2 — Hash**

```sql
EXEC dbo.HashConsumerSecrets
    @Schema    = N'dbo',
    @BatchSize = 500;
-- @EnableBackup defaults to 0 (backup skipped)
```

---

## Option B — With in-table backup (optional)

Use this when a full database snapshot cannot be taken before the migration. The backup enables rollback via `RestoreConsumerSecrets` and cleanup via `DropConsumerSecretsBackup`.

**Step 1 — Create all three procedures**

```sql
-- Run each file once to register the stored procedures
:r HashConsumerSecrets.sql
:r RestoreConsumerSecrets.sql
:r DropConsumerSecretsBackup.sql
```

**Step 2 — Hash with backup enabled**

```sql
EXEC dbo.HashConsumerSecrets
    @Schema       = N'dbo',
    @BatchSize    = 500,
    @EnableBackup = 1;
-- Backup table: dbo.IDN_OAUTH_CONSUMER_APPS_SECRET_BAK_<yyyymmdd>
```

**Step 3 (rollback, if needed) — Restore from backup**

```sql
EXEC dbo.RestoreConsumerSecrets
    @Schema     = N'dbo',
    @BackupDate = N'20260421';   -- yyyymmdd suffix of the backup table
```

**Step 4 — Drop the backup table once the migration is confirmed**

```sql
-- Dry run (shows row count, does nothing):
EXEC dbo.DropConsumerSecretsBackup
    @Schema     = N'dbo',
    @BackupDate = N'20260421';

-- Actually drop:
EXEC dbo.DropConsumerSecretsBackup
    @Schema     = N'dbo',
    @BackupDate = N'20260421',
    @Confirm    = N'YES';
```

---

## Parameters — `HashConsumerSecrets`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `@Schema` | `dbo` | Schema containing `IDN_OAUTH_CONSUMER_APPS` |
| `@BatchSize` | `500` | Rows per transaction (1–10 000) |
| `@EnableBackup` | `0` | `1` = copy plain-text rows to a backup table before hashing |

---

## Notes

- **Idempotent** — already-hashed rows are skipped; safe to re-run.
- **Verification built-in** — each procedure throws on failure; a `Verification passed` message confirms success.
- **Clean up procedures** when done:
  ```sql
  DROP PROCEDURE dbo.HashConsumerSecrets;
  DROP PROCEDURE dbo.RestoreConsumerSecrets;
  DROP PROCEDURE dbo.DropConsumerSecretsBackup;
  ```
