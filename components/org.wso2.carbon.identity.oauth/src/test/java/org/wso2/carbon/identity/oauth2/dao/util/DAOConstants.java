/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dao.util;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.core.UserCoreConstants;

/**
 * DAO Constants.
 */
public final class DAOConstants {

    private DAOConstants() {

    }

    public static final String OAUTH_TOKEN_PERSISTENCE_POOL_SIZE = "OAuth.TokenPersistence.PoolSize";

    public static final String FRAMEWORK_PERSISTENCE_POOL_SIZE = "JDBCPersistenceManager.SessionDataPersist.PoolSize";

    public static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";

    public static final String CALLBACK_URL = "http://localhost:8080/sample/oauth2client";

    public static final String SAMPLE_TENANT_DOMAIN = "wso2.com";

    public static final int SAMPLE_TENANT_ID = 1;

    public static final String SAMPLE_DOMAIN = "SAMPLE_DOMAIN";

    public static final String VALID_SCOPE_1 = "VALID_SCOPE_1";

    public static final String VALID_SCOPE_2 = "VALID_SCOPE_2";

    public static final String INVALID_SCOPE = "INVALID_SCOPE";

    public static final String AUTHZ_CODE_STATUS_BY_CODE = "SELECT STATE FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE " +
            "AUTHORIZATION_CODE= ?";

    public static final String TOKEN_STATUS_BY_TOKE = "SELECT TOKEN_STATE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE " +
            "TOKEN_ID=?";

    public static final class DataProviders {

        /*
          callback url
          tenant domain
          tenant id
          user store name
         */
        public static final Object[][] DATA_HOLDER_TYPE_1 = new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN
                },
        };

        /*
          tenant domain
          tenant id
          user store name
          user type
          grant type
         */
        public static final Object[][] DATA_HOLDER_TYPE_2 = new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IWA_NTLM,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };

        /*
          tenant domain
          tenant id
          user store name
          user type
          grant type
          scope
          include expired
         */
        public static final Object[][] DATA_HOLDER_TYPE_3 = new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        true
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        true
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        true
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        true
                },
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        false
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        VALID_SCOPE_1,
                        false
                },
                // Invalid scope
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        INVALID_SCOPE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        INVALID_SCOPE,
                        false
                },
        };

        /*
          tenant domain
          tenant id
          user store name
          user type
          grant type
          include expired
         */
        public static final Object[][] DATA_HOLDER_TYPE_4 = new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        false
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                        false
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        true
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        false
                },
        };

        /*
          callback url
          tenant domain
          tenant id
          user store
          code status
         */
        public static final Object[][] DATA_HOLDER_TYPE_5 = new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.EXPIRED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.INACTIVE

                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.INACTIVE
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.AuthorizationCodeState.REVOKED
                },
        };

        /*
          tenant domain
          tenant id
          user store name
          user type
          grant type
          token status
         */
        public static final Object[][] DATA_HOLDER_TYPE_6 = new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                        OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                },
        };
    }

}
