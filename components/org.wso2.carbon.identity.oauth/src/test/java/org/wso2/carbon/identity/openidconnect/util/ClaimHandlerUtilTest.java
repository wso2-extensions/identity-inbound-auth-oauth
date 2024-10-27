/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.AssertJUnit.assertEquals;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN;

@Listeners(MockitoTestNGListener.class)
public class ClaimHandlerUtilTest {

    @Mock
    private OAuthAppDO mockOAuthAppDO;
    @Mock
    private CustomClaimsCallbackHandler mockJWTAccessTokenOIDCClaimsHandler;
    @Mock
    private CustomClaimsCallbackHandler mockOpenIDConnectCustomClaimsCallbackHandler;
    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic;
    MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    MockedStatic<IdentityUtil> identityUtilMockedStatic;
    MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;

    private final String openIDConnectIDTokenCustomClaimsHandlerClassName = "SAMLAssertionClaimsCallback";
    private final String jwtAccessTokenOIDCClaimsHandlerClassName = "JWTAccessTokenOIDCClaimsHandler";

    @BeforeMethod
    public void setUp() throws Exception {

        // Mock and initialize the OAuthServerConfiguration.
        oAuthServerConfigurationMockedStatic = mockStatic(OAuthServerConfiguration.class);
        mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        lenient().when(mockOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(300L);

        // Initialize the static mocks.
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);
        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);

        // Initialize the mocks.
        String openIDConnectIDTokenPackageName = "org.wso2.carbon.identity.openidconnect.";
        mockOAuthAppDO = mock(OAuthAppDO.class);
        mockJWTAccessTokenOIDCClaimsHandler = mock(openIDConnectIDTokenPackageName
                + jwtAccessTokenOIDCClaimsHandlerClassName);
        mockOpenIDConnectCustomClaimsCallbackHandler = mock(openIDConnectIDTokenPackageName
                + openIDConnectIDTokenCustomClaimsHandlerClassName);

        // Mock login tenant utils.
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getLoginTenantId)
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(-1234))
                .thenReturn(SUPER_TENANT_DOMAIN_NAME);

        // Mock the JWTAccessTokenOIDCClaimsHandler and OpenIDConnectCustomClaimsCallbackHandler.
        lenient().when(mockOAuthServerConfiguration.getJWTAccessTokenOIDCClaimsHandler())
                .thenReturn(mockJWTAccessTokenOIDCClaimsHandler);
        lenient().when(mockOAuthServerConfiguration.getOpenIDConnectCustomClaimsCallbackHandler())
                .thenReturn(mockOpenIDConnectCustomClaimsCallbackHandler);
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfigurationMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        identityUtilMockedStatic.close();
        oAuth2UtilMockedStatic.close();
    }

    @DataProvider(name = "getClaimsCallbackHandlerDataProvider")
    public Object[][] getClaimsCallbackHandlerDataProvider() {

        return new Object[][] {
                {true, "v0.0.0", openIDConnectIDTokenCustomClaimsHandlerClassName, false},
                {true, "v1.0.0", openIDConnectIDTokenCustomClaimsHandlerClassName, false},
                {true, "v2.0.0", jwtAccessTokenOIDCClaimsHandlerClassName, true},
                {false, "v0.0.0", openIDConnectIDTokenCustomClaimsHandlerClassName, false},
                {false, "v1.0.0", openIDConnectIDTokenCustomClaimsHandlerClassName, false},
                {false, "v2.0.0", openIDConnectIDTokenCustomClaimsHandlerClassName, true}
        };
    }

    @Test(dataProvider = "getClaimsCallbackHandlerDataProvider")
    public void testGetClaimsCallbackHandler(boolean isServerConfigEnabled, String appVersion, String className,
                                             boolean isAllowed)
            throws IdentityOAuth2Exception {

        // Mock the configuration for claims separation enabled on demand.
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN))
                .thenReturn(isServerConfigEnabled ? "true" : "false");

        // Mock the service provider and app version.
        lenient().when(mockOAuthAppDO.getOauthConsumerKey()).thenReturn("testConsumerKey");
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationVersion(appVersion);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                .thenReturn(serviceProvider);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.isAppVersionAllowed(
                        appVersion, ApplicationConstants.ApplicationVersion.APP_VERSION_V2))
                .thenReturn(isAllowed);

        CustomClaimsCallbackHandler result = ClaimHandlerUtil.getClaimsCallbackHandler(mockOAuthAppDO);
        String extractedClassName = extractClassName(result.toString());
        assertEquals(extractedClassName, className);
    }

    private String extractClassName(String mockClassName) {

        if (mockClassName == null || mockClassName.isEmpty()) {
            return "";
        }
        int lastDotIndex = mockClassName.lastIndexOf('.');
        if (lastDotIndex != -1) {
            mockClassName = mockClassName.substring(lastDotIndex + 1);
        }
        int dollarIndex = mockClassName.indexOf('$');
        if (dollarIndex != -1) {
            return mockClassName.substring(0, dollarIndex);
        }
        return mockClassName;
    }
}
