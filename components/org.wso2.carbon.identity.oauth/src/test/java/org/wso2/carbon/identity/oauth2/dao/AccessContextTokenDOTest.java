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
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.net.SocketException;

import static org.testng.Assert.assertTrue;

/**
 * Unit tests for AccessContextTokenDO.
 */
public class AccessContextTokenDOTest {

    private AccessContextTokenDO accessContextTokenDO;

    private AccessTokenDO newAccessTokenDO;

    private AccessTokenDO existingAccessTokenDO;

    private static final String ACCESS_TOKEN = "accessToken";

    private static final String CONSUMER_KEY = "consumerKey";

    private static final String USER_STORE_DOMAIN = "userStoreDomain";

    @BeforeClass
    public void initTest() throws SocketException {
        newAccessTokenDO = new AccessTokenDO();
        existingAccessTokenDO = new AccessTokenDO();

        accessContextTokenDO = new AccessContextTokenDO(ACCESS_TOKEN, CONSUMER_KEY, newAccessTokenDO,
                existingAccessTokenDO, USER_STORE_DOMAIN);
    }

    @Test
    public void getAccessToken() {
        assertTrue(ACCESS_TOKEN.equals(accessContextTokenDO.getAccessToken()), "Failed to get access token.");
    }

    @Test
    public void getConsumerKey() {
        assertTrue(CONSUMER_KEY.equals(accessContextTokenDO.getConsumerKey()), "Failed to get consumer key.");
    }

    @Test
    public void getNewAccessTokenDO() {
        assertTrue(newAccessTokenDO.equals(accessContextTokenDO.getNewAccessTokenDO()), "Failed to get new access " +
                "token DO.");
    }

    @Test
    public void getUserStoreDomain() {
        assertTrue(USER_STORE_DOMAIN.equals(accessContextTokenDO.getUserStoreDomain()), "Failed to get user store " +
                "domain.");
    }

    @Test
    public void getExistingAccessTokenDO() {
        assertTrue(existingAccessTokenDO.equals(accessContextTokenDO.getExistingAccessTokenDO()), "Failed to get " +
                "existing access token DO.");
    }
}
