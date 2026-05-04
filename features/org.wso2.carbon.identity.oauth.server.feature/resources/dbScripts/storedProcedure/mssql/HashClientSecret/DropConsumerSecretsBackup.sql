/* =======================================================================
   Drop a CONSUMER_SECRET backup table created by HashConsumerSecrets.
   USAGE:
     1. Run this file once to (re)create the procedure.
     2. After the rollback window has elapsed and hashing is verified:
           EXEC dbo.DropConsumerSecretsBackup
                @Schema     = N'dbo',
                @BackupDate = N'20260421',
                @Confirm    = N'YES';
     3. Optionally drop this procedure itself:
           DROP PROCEDURE dbo.DropConsumerSecretsBackup;
======================================================================= */

CREATE   PROCEDURE dbo.DropConsumerSecretsBackup
    @Schema     SYSNAME  = N'dbo',
    @BackupDate CHAR(8)  = NULL,        -- yyyymmdd suffix, e.g. '20260421'
    @Confirm    NVARCHAR(10) = NULL     -- must be N'YES' to actually drop
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @BackupDate IS NULL
       OR @BackupDate NOT LIKE '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'
        THROW 51000, '@BackupDate must be an 8-digit yyyymmdd suffix of the backup table.', 1;

    DECLARE @AppsTbl NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(N'IDN_OAUTH_CONSUMER_APPS');
    DECLARE @BakName SYSNAME       = N'IDN_OAUTH_CONSUMER_APPS_SECRET_BAK_' + @BackupDate;
    DECLARE @BakTbl  NVARCHAR(300) = QUOTENAME(@Schema) + N'.' + QUOTENAME(@BakName);
    DECLARE @Sql     NVARCHAR(MAX);

    IF OBJECT_ID(@BakTbl, N'U') IS NULL
    BEGIN
        PRINT CONCAT('Backup table ', @BakTbl, ' does not exist. Nothing to drop.');
        RETURN;
    END;

    ---------------------------------------------------------------------
    -- Safety check: live table must be fully hashed (or empty of secrets).
    ---------------------------------------------------------------------
    IF OBJECT_ID(@AppsTbl, N'U') IS NULL
        THROW 51001, 'IDN_OAUTH_CONSUMER_APPS does not exist in the supplied schema.', 1;

    DECLARE @PlainRows INT;
    SET @Sql = N'
        SELECT @n = COUNT(*)
        FROM   ' + @AppsTbl + N'
        WHERE  CONSUMER_SECRET IS NOT NULL
          AND  CONSUMER_SECRET NOT LIKE ''{"hash":%''
          AND  CONSUMER_SECRET NOT LIKE ''{"algorithm":%'';';
    EXEC sp_executesql @Sql, N'@n INT OUTPUT', @n = @PlainRows OUTPUT;

    IF @PlainRows > 0
        THROW 51002,
            'Refusing to drop: live IDN_OAUTH_CONSUMER_APPS still has plaintext CONSUMER_SECRET rows. Finish hashing first.',
            1;

    ---------------------------------------------------------------------
    -- Confirmation latch.
    ---------------------------------------------------------------------
    IF @Confirm IS NULL OR UPPER(@Confirm) <> N'YES'
    BEGIN
        DECLARE @RowCount INT;
        SET @Sql = N'SELECT @n = COUNT(*) FROM ' + @BakTbl + N';';
        EXEC sp_executesql @Sql, N'@n INT OUTPUT', @n = @RowCount OUTPUT;

        PRINT CONCAT('DRY RUN. Backup table ', @BakTbl,
                     ' holds ', @RowCount, ' plaintext row(s).');
        PRINT 'Re-run with @Confirm = N''YES'' to drop it permanently.';
        RETURN;
    END;

    ---------------------------------------------------------------------
    -- Drop.
    ---------------------------------------------------------------------
    SET @Sql = N'DROP TABLE ' + @BakTbl + N';';
    EXEC sp_executesql @Sql;

    PRINT CONCAT('Dropped ', @BakTbl, '.');
END;