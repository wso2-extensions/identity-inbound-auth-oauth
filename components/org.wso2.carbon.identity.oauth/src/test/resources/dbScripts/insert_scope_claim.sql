INSERT INTO IDN_CLAIM_DIALECT(ID,DIALECT_URI,TENANT_ID) VALUES (5,'http://wso2.org/oidc/claim',1234);

INSERT INTO IDN_OAUTH2_SCOPE (SCOPE_ID, NAME, DISPLAY_NAME, TENANT_ID, SCOPE_TYPE) VALUES
            (1, 'address', 'address', 1234, 'OIDC');
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (501, 5,'address.country', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (1, 1,501);
INSERT INTO IDN_OAUTH2_SCOPE (SCOPE_ID, NAME, DISPLAY_NAME, TENANT_ID, SCOPE_TYPE) VALUES
            (2, 'openid', 'openid', 1234, 'OIDC');
INSERT INTO IDN_OAUTH2_SCOPE (SCOPE_ID, NAME, DISPLAY_NAME, TENANT_ID, SCOPE_TYPE) VALUES
            (3, 'groups', 'groups', 1234, 'OIDC');
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (502, 5,'username', 1234);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (503, 5,'address', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (2, 2,502);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (3, 2,503);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (504, 5,'email', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (4, 2,504);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (505, 5,'role', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (5, 2,505);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (506, 5,'phone_number_verified', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (6, 2,506);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (507, 5,'updated_at', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (7, 2,507);
INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (508, 5,'email_verified', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (8, 2,508);

INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (9, 2,501);

INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (510, 5,'http://wso2.com.division', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (10, 2,510);

INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (511, 5,'org.division', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (11, 2,511);

INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (515, 5,'division', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (15, 2,515);

INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (513, 5,'country', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (13, 2,513);

INSERT INTO IDN_CLAIM (ID, DIALECT_ID, CLAIM_URI,TENANT_ID) VALUES
            (514, 5,'groups', 1234);
INSERT INTO IDN_OIDC_SCOPE_CLAIM_MAPPING  (ID, SCOPE_ID, EXTERNAL_CLAIM_ID) VALUES
            (14, 3,514);
INSERT INTO IDN_CLAIM_DIALECT(ID,DIALECT_URI,TENANT_ID) VALUES (5,'http://wso2.org/oidc/claim',1234);