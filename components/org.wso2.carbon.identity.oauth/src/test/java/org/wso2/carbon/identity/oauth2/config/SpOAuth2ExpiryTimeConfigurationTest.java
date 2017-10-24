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

package org.wso2.carbon.identity.oauth2.config;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.junit.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class SpOAuth2ExpiryTimeConfigurationTest extends PowerMockIdentityBaseTest {

    private static final String CONSUMER_KEY = "consumer_key";
    private static final long TOKEN_EXPIRY_TIME = 3600L;

    SpOAuth2ExpiryTimeConfiguration spOAuth2ExpiryTimeConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {
        spOAuth2ExpiryTimeConfiguration = new SpOAuth2ExpiryTimeConfiguration();
    }

    @Test
    public void testGetConsumerKey() throws Exception {
        spOAuth2ExpiryTimeConfiguration.setConsumerKey(CONSUMER_KEY);
        assertEquals(spOAuth2ExpiryTimeConfiguration.getConsumerKey(), CONSUMER_KEY);
    }

    @Test
    public void testSetConsumerKey() throws Exception {
        assertNull(spOAuth2ExpiryTimeConfiguration.getConsumerKey());
        spOAuth2ExpiryTimeConfiguration.setConsumerKey(CONSUMER_KEY);
        assertEquals(spOAuth2ExpiryTimeConfiguration.getConsumerKey(), CONSUMER_KEY);
    }

    @Test
    public void testSetUserAccessTokenExpiryTime() throws Exception {
        assertNull(spOAuth2ExpiryTimeConfiguration.getUserAccessTokenExpiryTime());
        spOAuth2ExpiryTimeConfiguration.setUserAccessTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getUserAccessTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }

    @Test
    public void testGetUserAccessTokenExpiryTime() throws Exception {
        spOAuth2ExpiryTimeConfiguration.setUserAccessTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getUserAccessTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }

    @Test
    public void testGetRefreshTokenExpiryTime() throws Exception {
        spOAuth2ExpiryTimeConfiguration.setRefreshTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getRefreshTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }

    @Test
    public void testSetRefreshTokenExpiryTime() throws Exception {
        assertNull(spOAuth2ExpiryTimeConfiguration.getRefreshTokenExpiryTime());
        spOAuth2ExpiryTimeConfiguration.setRefreshTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getRefreshTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }

    @Test
    public void testSetApplicationAccessTokenExpiryTime() throws Exception {
        assertNull(spOAuth2ExpiryTimeConfiguration.getApplicationAccessTokenExpiryTime());
        spOAuth2ExpiryTimeConfiguration.setApplicationAccessTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getApplicationAccessTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }

    @Test
    public void testGetApplicationAccessTokenExpiryTime() throws Exception {
        spOAuth2ExpiryTimeConfiguration.setApplicationAccessTokenExpiryTime(TOKEN_EXPIRY_TIME);
        assertTrue(spOAuth2ExpiryTimeConfiguration.getApplicationAccessTokenExpiryTime() == TOKEN_EXPIRY_TIME);
    }
}
