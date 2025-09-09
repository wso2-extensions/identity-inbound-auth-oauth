-- Create an access token that is time-expired (1h validity, issued >1h ago) with a refresh token that is still valid.
INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID,
            USER_DOMAIN, USER_TYPE, GRANT_TYPE, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD,
            REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, TOKEN_STATE, TOKEN_STATE_ID, SUBJECT_IDENTIFIER,
            ACCESS_TOKEN_HASH, REFRESH_TOKEN_HASH, IDP_ID) VALUES
            ('expired_token_id', 'expired_access_token', 'active_refresh_token', 1,
            'user1', 1234, 'PRIMARY', 'APPLICATION_USER', 'authorization_code', '2024-01-01 10:00:00', NOW(), 3600000,
            14400000, 'token_scope_hash', 'ACTIVE', 'NONE', 'user1', 'access_token_hash', 'refresh_token_hash', 1);

INSERT INTO IDN_OAUTH2_ACCESS_TOKEN_SCOPE (TOKEN_ID, TOKEN_SCOPE, TENANT_ID) VALUES
    ('expired_token_id', 'openid', 1234);