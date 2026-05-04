/* =======================================================================
   Restore plain-text CONSUMER_SECRET from a prior-run backup table.
   Counterpart to hash-consumer-secrets-mssql.sql (stored procedure form).

   Restores IDN_OAUTH_CONSUMER_APPS.CONSUMER_SECRET for every ID in
   <schema>.IDN_OAUTH_CONSUMER_APPS_SECRET_BAK_<yyyymmdd>.

   USAGE:
     1. Run this file once to (re)create the procedure.
     2. Execute it with your schema and the backup date suffix:
           EXEC dbo.RestoreConsumerSecrets
                @Schema     = N'dbo',
                @BackupDate = N'20260421';
     3. Optionally drop it afterwards:
           DROP PROCEDURE dbo.RestoreConsumerSecrets;
======================================================================= */

CREATE   PROCEDURE dbo.RestoreConsumerSecrets
    @Schema     SYSNAME  = N'dbo',
    @BackupDate CHAR(8)  = NULL,        -- yyyymmdd suffix of the backup table, e.g. '20260421'
    @BatchSize  INT      = 500
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @BackupDate IS NULL
       OR @BackupDate NOT LIKE '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'
        THROW 51000, '@BackupDate must be an 8-digit yyyymmdd suffix of the backup table.', 1;

    IF @BatchSize IS NULL OR @BatchSize <= 0 OR @BatchSize > 10000
        THROW 51001, '@BatchSize must be between 1 and 10000.', 1;

    DECLARE @AppsTbl NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(N'IDN_OAUTH_CONSUMER_APPS');
    DECLARE @BakName SYSNAME       = N'IDN_OAUTH_CONSUMER_APPS_SECRET_BAK_' + @BackupDate;
    DECLARE @BakTbl  NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(@BakName);
    DECLARE @Sql     NVARCHAR(MAX);

    IF OBJECT_ID(@AppsTbl, N'U') IS NULL
        THROW 51002, 'IDN_OAUTH_CONSUMER_APPS does not exist in the supplied schema.', 1;
    IF OBJECT_ID(@BakTbl, N'U') IS NULL
        THROW 51003, 'Backup table does not exist for the supplied @BackupDate.', 1;

    DECLARE @BakRows INT;
    SET @Sql = N'SELECT @n = COUNT(*) FROM ' + @BakTbl + N';';
    EXEC sp_executesql @Sql, N'@n INT OUTPUT', @n = @BakRows OUTPUT;
    PRINT CONCAT('Backup table rows available for restore: ', @BakRows);

    IF @BakRows = 0
    BEGIN
        PRINT 'Backup table is empty. Nothing to restore.';
        RETURN;
    END;

    ---------------------------------------------------------------------
    -- Batched UPDATE: join live table to backup, overwrite with plain.
    -- Skip rows already matching the backup (idempotent re-runs).
    ---------------------------------------------------------------------
    DECLARE @Rows INT = 1;
    DECLARE @TotalRestored BIGINT = 0;

    WHILE @Rows > 0
    BEGIN
        BEGIN TRY
            BEGIN TRAN;

            SET @Sql = N'
                ;WITH candidates AS (
                    SELECT TOP (@bs) a.ID,
                           a.CONSUMER_SECRET AS CURRENT_SECRET,
                           b.CONSUMER_SECRET AS RESTORE_SECRET
                    FROM   ' + @AppsTbl + N' a WITH (ROWLOCK, READPAST)
                    JOIN   ' + @BakTbl  + N' b ON b.ID = a.ID
                    WHERE  (a.CONSUMER_SECRET IS NULL AND b.CONSUMER_SECRET IS NOT NULL)
                       OR  (a.CONSUMER_SECRET IS NOT NULL AND b.CONSUMER_SECRET IS NULL)
                       OR  (a.CONSUMER_SECRET <> b.CONSUMER_SECRET)
                    ORDER BY a.ID
                )
                UPDATE candidates
                SET    CURRENT_SECRET = RESTORE_SECRET;
                SET @r = @@ROWCOUNT;';
            EXEC sp_executesql @Sql,
                 N'@bs INT, @r INT OUTPUT',
                 @bs = @BatchSize, @r = @Rows OUTPUT;

            SET @TotalRestored += @Rows;
            COMMIT TRAN;
        END TRY
        BEGIN CATCH
            IF XACT_STATE() <> 0 ROLLBACK TRAN;
            THROW;
        END CATCH;
    END;

    PRINT CONCAT('Rows restored: ', @TotalRestored);

  ---------------------------------------------------------------------
    -- Verification: every backup row must now match the live row.
    ---------------------------------------------------------------------
    DECLARE @Mismatch INT;
    SET @Sql = N'
        SELECT @m = COUNT(*)
        FROM   ' + @BakTbl  + N' b
        JOIN   ' + @AppsTbl + N' a ON a.ID = b.ID
        WHERE  (a.CONSUMER_SECRET IS NULL AND b.CONSUMER_SECRET IS NOT NULL)
           OR  (a.CONSUMER_SECRET IS NOT NULL AND b.CONSUMER_SECRET IS NULL)
           OR  (a.CONSUMER_SECRET <> b.CONSUMER_SECRET);';
    EXEC sp_executesql @Sql, N'@m INT OUTPUT', @m = @Mismatch OUTPUT;

    IF @Mismatch > 0
        THROW 51004, 'Verification failed: some live CONSUMER_SECRET values do not match the backup.', 1;

    -- Informational: backup IDs that no longer exist in the live table.
    DECLARE @Missing INT;
    SET @Sql = N'
        SELECT @m = COUNT(*)
        FROM   ' + @BakTbl  + N' b
        LEFT  JOIN ' + @AppsTbl + N' a ON a.ID = b.ID
        WHERE  a.ID IS NULL;';
    EXEC sp_executesql @Sql, N'@m INT OUTPUT', @m = @Missing OUTPUT;

    IF @Missing > 0
        PRINT CONCAT('WARNING: ', @Missing,
                     ' row(s) in the backup no longer exist in IDN_OAUTH_CONSUMER_APPS and were not restored.');

    PRINT 'Verification passed.';
END;
