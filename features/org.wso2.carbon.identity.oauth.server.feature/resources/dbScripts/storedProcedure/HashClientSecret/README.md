# Hash Consumer Secrets 

Migrates plain-text `CONSUMER_SECRET` values in `IDN_OAUTH_CONSUMER_APPS` to SHA-256 hashes of the form:

```
{"hash":"<sha256-hex-lowercase>","algorithm":"SHA-256"}
```

---

> **Warning:** This operation is irreversible. Take a full database backup before proceeding.

## Notes

- **Idempotent** — already-hashed rows are skipped; safe to re-run.
- **Verification built-in** — the procedure throws on failure; a `Verification passed` message confirms success.

## Hash Consumer Secrets — MSSQL

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

### Parameters — `HashConsumerSecrets`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `@Schema` | `dbo` | Schema containing `IDN_OAUTH_CONSUMER_APPS` |
| `@BatchSize` | `500` | Rows per transaction (1–10 000) |

---

## Hash Consumer Secrets — Postgre 14 and 14+

**Step 1 — Create the procedure**

```sql
\i postgre.sql
```

**Step 2 — Hash**

```sql
CALL HashConsumerSecrets(
    'public',
    500
);
```

**Step 3 — Drop the procedure when done**

```sql
DROP PROCEDURE HashConsumerSecrets(TEXT, INT);
```

---

### Parameters — `HashConsumerSecrets`

| Parameter | Default  | Description |
|-----------|----------|-------------|
| `@Schema` | `public` | Schema containing `IDN_OAUTH_CONSUMER_APPS` |
| `@BatchSize` | `500`    | Rows per transaction (1–10 000) |

---
