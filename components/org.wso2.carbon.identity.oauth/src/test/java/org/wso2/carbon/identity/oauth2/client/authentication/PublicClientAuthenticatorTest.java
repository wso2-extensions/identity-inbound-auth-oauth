/*
 * Copyright (c) 2018-2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.apache.axis2.transport.http.HTTPConstants;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * This class contains the test cased related to the public client authentication functionality.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class PublicClientAuthenticatorTest {

    private final PublicClientAuthenticator publicClientAuthenticator = new PublicClientAuthenticator();
    private final List<String> publicClientSupportedGrantTypes = new ArrayList<>();
    private static final String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static final String CLIENT_ID = "someClientId";
    private static final String CLIENT_SECRET = "someClientSecret";
    private static final String APPLICATION_NAME = "someApplicationName";
    private static final String GRANT_TYPE = "someGrantType";
    private static final String TEST_ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private HttpServletRequest mockedHttpServletRequest;

    @Mock
    private OAuthAdminServiceImpl mockedOAuthAdminService;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private OAuth2ServiceComponentHolder mockedInstance;

    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic;

    @BeforeMethod
    public void setUp() {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setOrganizationId(TEST_ORG_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        identityUtil = mockStatic(IdentityUtil.class);
        oAuth2ServiceComponentHolderMockedStatic = mockStatic(OAuth2ServiceComponentHolder.class);
        oAuthServerConfigurationMockedStatic = mockStatic(OAuthServerConfiguration.class);
        identityUtil.when(IdentityUtil::getIdentityConfigDirPath)
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");
        oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance).thenReturn(mockedServerConfig);
        publicClientSupportedGrantTypes.add(GRANT_TYPE);
        oAuth2Util = mockStatic(OAuth2Util.class);
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        oAuth2Util.close();
        oAuth2ServiceComponentHolderMockedStatic.close();
        oAuthServerConfigurationMockedStatic.close();
    }

    @Test
    public void testGetPriority() {

        assertEquals(200, publicClientAuthenticator.getPriority(),
                "Default priority of the public client authenticator has changed");
    }

    /**
     * Test for client authentication.
     *
     * @param headerName    Header name.
     * @param headerValue   Header value.
     * @param bodyContent   Message body content.
     * @param publicClient  Flag for public client state.
     * @param canHandle     Flag for authentication handle state.
     * @throws Exception    Exception.
     */
    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(String headerName, String headerValue, HashMap<String, List> bodyContent,
                                    boolean publicClient, boolean canHandle,
                                    List<String> publicClientSupportedGrantTypes) throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setBypassClientCredentials(publicClient);
        appDO.setApplicationName(APPLICATION_NAME);

        when(mockedServerConfig.getPublicClientSupportedGrantTypesList())
                .thenReturn(publicClientSupportedGrantTypes);
        lenient().when(mockedHttpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(appDO);

        assertEquals(publicClientAuthenticator.canAuthenticate(mockedHttpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    /**
     * Test for authentication scenarios.
     *
     * @return An object array containing authentication data.
     */
    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                // Correct Authorization header with valid client id and secret. Also a Public client.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true, false,
                        publicClientSupportedGrantTypes},

                // Correct Authorization header with valid client id and secret. Not a Public client. But no grant type
                // is allowed for public clients.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true, false,
                        new ArrayList<>()},

                // Simple case correct authorization header with valid client id and secret. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true, false,
                        publicClientSupportedGrantTypes},

                // Simple case authorization header value without "Basic" prefix. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Some value without Basic part", new HashMap<String, List>(),
                        true, false, publicClientSupportedGrantTypes},

                // Simple case authorization header value with "Basic" prefix. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Basic some value with Basic part", new HashMap<String, List>(),
                        true, false, publicClientSupportedGrantTypes},

                // Simple authorization header with null value. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, new HashMap<String, List>(), true, false,
                        publicClientSupportedGrantTypes},

                // Simple authorization header but no value. But has client id and secret in body. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID,
                        CLIENT_SECRET), true, true, publicClientSupportedGrantTypes},

                // No authorization header. but client id and secret present in the body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), true, true,
                        publicClientSupportedGrantTypes},

                // No authorization header. but client id and secret present in the body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), false, false,
                        publicClientSupportedGrantTypes},

                // No authorization header. Only client secret is present in body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, CLIENT_SECRET),
                        true, false, publicClientSupportedGrantTypes},

                // No authorization header. Only client secret is present in body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, CLIENT_SECRET),
                        false, false, publicClientSupportedGrantTypes},

                // No authorization header. Only client id is present in the body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, null), true, true,
                        publicClientSupportedGrantTypes},

                // No authorization header. Only client id is present in the body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, null), false, false,
                        publicClientSupportedGrantTypes},

                // Neither authorization header nor body parameters present and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, null),
                        true, false, publicClientSupportedGrantTypes},

                // Neither authorization header nor body parameters present and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, null), false, false,
                        publicClientSupportedGrantTypes},
        };
    }

    @DataProvider(name = "testPublicClientSharedAppInAPIBasedAuthFlowData")
    public Object[][] testPublicClientSharedAppInAPIBasedAuthFlowData() {

        return new Object[][] {

                // Only Shared Application isPublicClient property is true.
                { ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET),
                        true, false, true },

                // Only Parent Application isPublicClient property is true.
                { ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET),
                        false, true, true },

                // Both Shared Application and Parent Application isPublicClient property is true.
                { ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET),
                        true, true, true },

                // Both Shared Application and Parent Application isPublicClient property is false.
                { ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET),
                        false, false, false },

                // isPublicClient property is true for both but client id and secret is not present in the body.
                { ClientAuthUtil.getBodyContentWithClientAndSecret(null, null),
                        true, true, false }
        };
    }

    /**
     * Test for Public Client Shared Application in API Based Authentication Flow.
     *
     * @param isPublicClient       Flag for public client state of shared application.
     * @param isPublicClientParent Flag for public client state of parent application.
     * @param canHandle            Flag for authentication handle state.
     * @throws Exception           Exception.
     */
    @Test(dataProvider = "testPublicClientSharedAppInAPIBasedAuthFlowData")
    public void testPublicClientSharedAppInAPIBasedAuthFlow(HashMap<String, List> bodyContent, boolean isPublicClient,
                                                            boolean isPublicClientParent, boolean canHandle)
            throws Exception {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setBypassClientCredentials(isPublicClient);
        appDO.setApplicationName(APPLICATION_NAME);

        OAuthConsumerAppDTO mainOAuthAppDO = new OAuthConsumerAppDTO();
        mainOAuthAppDO.setBypassClientCredentials(isPublicClientParent);

        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(appDO);
        oAuth2Util.when(() -> OAuth2Util.isApiBasedAuthenticationFlow(mockedHttpServletRequest)).thenReturn(true);
        when(mockedServerConfig.getPublicClientSupportedGrantTypesList()).thenReturn(publicClientSupportedGrantTypes);
        when(OAuth2ServiceComponentHolder.getInstance()).thenReturn(mockedInstance);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockedApplicationManagementService);
        lenient().when(mockedInstance.getOAuthAdminService()).thenReturn(mockedOAuthAdminService);
        lenient().when(mockedOAuthAdminService.getOAuthApplicationDataByAppName(APPLICATION_NAME, 0))
                .thenReturn(mainOAuthAppDO);
        lenient().when(mockedHttpServletRequest.getHeader(SIMPLE_CASE_AUTHORIZATION_HEADER)).thenReturn(null);

        assertEquals(publicClientAuthenticator.canAuthenticate(mockedHttpServletRequest, bodyContent,
                new OAuthClientAuthnContext()), canHandle, "Expected authenticate evaluation not received");
    }
}
