/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.fapi.utils;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for {@link FapiUtil}.
 */
public class FapiUtilTest {

    private static final String TENANT_DOMAIN = "r3.com";
    private static final String ENTITY_ID = "https://localhost:9443/oauth2/oidcdiscovery";
    private static final String BASE_ISSUER = "https://localhost:9443/t/r3.com";

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;

    @BeforeClass
    public void setUp() {

        // OAuth2Util reads the server configuration when it is initialized.
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mock(OAuthServerConfiguration.class));
    }

    @AfterClass
    public void tearDown() {

        oAuthServerConfiguration.close();
    }

    @DataProvider(name = "fapi2IdTokenIssuerData")
    public Object[][] fapi2IdTokenIssuerData() {

        return new Object[][]{
                // FAPI 2.0 enabled, IS 7.1 FAPI version configuration, resident IdP entity ID, client ID, issuer.
                {false, false, ENTITY_ID, "r3-app", null},
                {true, false, ENTITY_ID, "r3-app", BASE_ISSUER},
                {true, false, ENTITY_ID, null, BASE_ISSUER},
                {true, false, ENTITY_ID, "MY_ACCOUNT", null},
                {true, false, ENTITY_ID, "CONSOLE", null},
                {true, true, ENTITY_ID, "r3-app", ENTITY_ID},
                {true, true, ENTITY_ID, "MY_ACCOUNT", ENTITY_ID},
                {true, true, "", "r3-app", BASE_ISSUER},
                {true, true, "", "MY_ACCOUNT", null},
        };
    }

    @Test(dataProvider = "fapi2IdTokenIssuerData")
    public void testGetFapi2IdTokenIssuer(boolean isFapi2Enabled, boolean isFapi2EnabledByServerConfig,
                                          String residentIdpEntityId, String clientId, String expectedIssuer)
            throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<FapiUtil> fapiUtil = mockStatic(FapiUtil.class, CALLS_REAL_METHODS)) {
            oAuth2Util.when(() -> OAuth2Util.isFapi2Enabled(TENANT_DOMAIN)).thenReturn(isFapi2Enabled);
            oAuth2Util.when(() -> OAuth2Util.getResidentIdpEntityId(TENANT_DOMAIN)).thenReturn(residentIdpEntityId);
            oAuth2Util.when(() -> OAuth2Util.buildBaseIssuerUrl(TENANT_DOMAIN)).thenReturn(BASE_ISSUER);
            fapiUtil.when(FapiUtil::isFapi2EnabledByServerConfig).thenReturn(isFapi2EnabledByServerConfig);

            Assert.assertEquals(FapiUtil.getFapi2IdTokenIssuer(TENANT_DOMAIN, clientId), expectedIssuer);
        }
    }
}
