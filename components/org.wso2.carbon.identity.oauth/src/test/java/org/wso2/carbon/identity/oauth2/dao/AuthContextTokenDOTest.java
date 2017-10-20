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

package org.wso2.carbon.identity.oauth2.dao;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import java.net.SocketException;

import static org.testng.Assert.assertTrue;

/**
 * Unit tests for AuthContextTokenDO.
 */
public class AuthContextTokenDOTest extends IdentityBaseTest {

    private static final String AUTHZ_CODE = "authzCode";

    private static final String CONSUMER_KEY = "consumerKeyy";

    private static final String CALLBACK_URL = "callbackUrl";

    private static final String TOKEN_ID = "tokenId";

    private AuthzCodeDO authzCodeDO;

    private AuthContextTokenDO authContextTokenDO;

    @BeforeClass
    public void initTest() throws SocketException {
        authzCodeDO = new AuthzCodeDO();

        authContextTokenDO = new AuthContextTokenDO(AUTHZ_CODE, CONSUMER_KEY, CALLBACK_URL, authzCodeDO);
    }

    @Test
    public void getTokenId() {
        AuthContextTokenDO authContextTokenDO = new AuthContextTokenDO(AUTHZ_CODE, TOKEN_ID);
        assertTrue(TOKEN_ID.equals(authContextTokenDO.getTokenId()), "Failed to get token id.");
    }

    @Test
    public void getAuthzCode() {
        AuthContextTokenDO authContextTokenDO = new AuthContextTokenDO(AUTHZ_CODE);
        assertTrue(AUTHZ_CODE.equals(authContextTokenDO.getAuthzCode()), "Failed to get authz code.");
    }

    @Test
    public void getConsumerKey() {
        assertTrue(CONSUMER_KEY.equals(authContextTokenDO.getConsumerKey()), "Failed to get consumer key");
    }

    @Test
    public void getCallbackUrl() {
        assertTrue(CALLBACK_URL.equals(authContextTokenDO.getCallbackUrl()), "Failed to get callback url.");
    }

    @Test
    public void getAuthzCodeDO() {
        assertTrue(authzCodeDO.equals(authContextTokenDO.getAuthzCodeDO()), "Failed to get authz code do.");
    }
}
