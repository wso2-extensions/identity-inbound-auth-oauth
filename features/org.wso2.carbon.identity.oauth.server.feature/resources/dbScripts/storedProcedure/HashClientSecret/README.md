# Hash Consumer Secrets — MSSQL

Migrates plain-text `CONSUMER_SECRET` values in `IDN_OAUTH_CONSUMER_APPS` to SHA-256 hashes of the form:

```
{"hash":"<sha256-hex-lowercase>","algorithm":"SHA-256"}
```

---

> **Warning:** This operation is irreversible. Take a full database backup before proceeding.

**Step 1 — Create the procedure**

```sql
:r mssql.sql
```

**Step 2 — Hash**

```sql
EXEC dbo.HashConsumerSecrets
    @Schema    = N'dbo',
    @BatchSize = 500;
```

**Step 3 — Drop the procedure when done**

```sql
DROP PROCEDURE dbo.HashConsumerSecrets;
```

---

## Parameters — `HashConsumerSecrets`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `@Schema` | `dbo` | Schema containing `IDN_OAUTH_CONSUMER_APPS` |
| `@BatchSize` | `500` | Rows per transaction (1–10 000) |

---

## Notes

- **Idempotent** — already-hashed rows are skipped; safe to re-run.
- **Verification built-in** — the procedure throws on failure; a `Verification passed` message confirms success.
