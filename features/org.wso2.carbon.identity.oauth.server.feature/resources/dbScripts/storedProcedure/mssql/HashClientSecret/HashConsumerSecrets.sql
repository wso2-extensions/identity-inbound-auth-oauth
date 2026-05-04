/* =======================================================================
   Hash plain-text CONSUMER_SECRET in IDN_OAUTH_CONSUMER_APPS (MSSQL)
   Target format (matches client-secret-only hash processor):
     {"hash":"<sha256-hex-lowercase>","algorithm":"SHA-256"}

   USAGE:
     1. Run this file once to (re)create the procedure.
     2. Execute it with your schema:
           EXEC dbo.HashConsumerSecrets @Schema = N'dbo', @BatchSize = 500;
        Pass @EnableBackup = 1 to capture plaintext rows in a backup table
        before hashing (disabled by default — use only when a full DB backup
        cannot be taken beforehand):
     3. Optionally drop it after the migration:
           DROP PROCEDURE dbo.HashConsumerSecrets;
======================================================================= */

CREATE   PROCEDURE dbo.HashConsumerSecrets
    @Schema        SYSNAME = N'dbo',
    @BatchSize     INT     = 500,
    @EnableBackup  BIT     = 0      -- 0 = skip backup (default); 1 = capture plaintext in backup table first
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @BatchSize IS NULL OR @BatchSize <= 0 OR @BatchSize > 10000
        THROW 51000, '@BatchSize must be between 1 and 10000.', 1;

    DECLARE @AppsTbl NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(N'IDN_OAUTH_CONSUMER_APPS');
    DECLARE @BakName SYSNAME       = N'IDN_OAUTH_CONSUMER_APPS_SECRET_BAK_'
                                      + CONVERT(CHAR(8), GETUTCDATE(), 112);
    DECLARE @BakTbl  NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(@BakName);
    DECLARE @Sql     NVARCHAR(MAX);

    IF OBJECT_ID(@AppsTbl, N'U') IS NULL
        THROW 51001, 'IDN_OAUTH_CONSUMER_APPS does not exist in the supplied schema.', 1;

    ---------------------------------------------------------------------
    -- 1. Backup (only when @EnableBackup = 1).
    ---------------------------------------------------------------------
    IF @EnableBackup = 1
    BEGIN
        IF OBJECT_ID(@BakTbl, N'U') IS NULL
        BEGIN
            SET @Sql = N'
                CREATE TABLE ' + @BakTbl + N' (
                    ID               INT           NOT NULL,
                    TENANT_ID        INT           NOT NULL,
                    CONSUMER_KEY     VARCHAR(255)  NULL,
                    CONSUMER_SECRET  VARCHAR(2048) NULL,
                    BACKED_UP_AT_UTC DATETIME2(3)  NOT NULL
                        CONSTRAINT ' + QUOTENAME(N'DF_' + @BakName + N'_ts')
                        + N' DEFAULT SYSUTCDATETIME(),
                    CONSTRAINT ' + QUOTENAME(N'PK_' + @BakName) + N' PRIMARY KEY (ID)
                );';
            EXEC sp_executesql @Sql;
        END;

        SET @Sql = N'
            INSERT INTO ' + @BakTbl + N' (ID, TENANT_ID, CONSUMER_KEY, CONSUMER_SECRET)
            SELECT a.ID, a.TENANT_ID, a.CONSUMER_KEY, a.CONSUMER_SECRET
            FROM   ' + @AppsTbl + N' a
            LEFT  JOIN ' + @BakTbl + N' b ON b.ID = a.ID
            WHERE  b.ID IS NULL
              AND  a.CONSUMER_SECRET IS NOT NULL
              AND  a.CONSUMER_SECRET NOT LIKE ''{"hash":%''
              AND  a.CONSUMER_SECRET NOT LIKE ''{"algorithm":%'';';
        EXEC sp_executesql @Sql;

        PRINT CONCAT('Backup table ready: ', @BakTbl);
    END
    ELSE
        PRINT 'Backup skipped (@EnableBackup = 0). Ensure a full DB backup was taken before running.';

    ---------------------------------------------------------------------
    -- 2. Batched UPDATE. Per-batch transaction.
    ---------------------------------------------------------------------
    DECLARE @Rows INT = 1;
    DECLARE @TotalHashed BIGINT = 0;

    WHILE @Rows > 0
    BEGIN
        BEGIN TRY
            BEGIN TRAN;

            SET @Sql = N'
                ;WITH candidates AS (
                    SELECT TOP (@bs) ID, CONSUMER_SECRET
                    FROM   ' + @AppsTbl + N' WITH (ROWLOCK, READPAST)
                    WHERE  CONSUMER_SECRET IS NOT NULL
                      AND  CONSUMER_SECRET NOT LIKE ''{"hash":%''
                      AND  CONSUMER_SECRET NOT LIKE ''{"algorithm":%''
                    ORDER BY ID
                )
                UPDATE candidates
                SET    CONSUMER_SECRET =
                         ''{"hash":"''
                       + LOWER(CONVERT(VARCHAR(128),
                               HASHBYTES(''SHA2_256'',
                                         CONVERT(VARBINARY(MAX), CONSUMER_SECRET)), 2))
                       + ''","algorithm":"SHA-256"}'';
                SET @r = @@ROWCOUNT;';
            EXEC sp_executesql @Sql,
                 N'@bs INT, @r INT OUTPUT',
                 @bs = @BatchSize, @r = @Rows OUTPUT;

            SET @TotalHashed += @Rows;
            COMMIT TRAN;
        END TRY
        BEGIN CATCH
            IF XACT_STATE() <> 0 ROLLBACK TRAN;
            THROW;
        END CATCH;
    END;

    PRINT CONCAT('Rows hashed: ', @TotalHashed);

    ---------------------------------------------------------------------
    -- 3. Verification: every non-null secret must be JSON-wrapped with
    --    a 64-char lowercase hex digest inside.
    ---------------------------------------------------------------------
    DECLARE @BadRows INT;
    SET @Sql = N'
        SELECT @bad = COUNT(*)
        FROM   ' + @AppsTbl + N'
        WHERE  CONSUMER_SECRET IS NOT NULL
          AND  CONSUMER_SECRET NOT LIKE ''{"hash":"________________________________________________________________","algorithm":"SHA-256"}''
          AND  CONSUMER_SECRET NOT LIKE ''{"algorithm":"SHA-256","hash":"________________________________________________________________"}'';';
    EXEC sp_executesql @Sql, N'@bad INT OUTPUT', @bad = @BadRows OUTPUT;

    IF @BadRows > 0
        THROW 51002, 'Verification failed: some CONSUMER_SECRET values are not in the expected hashed JSON format.', 1;

    PRINT 'Verification passed.';
END;