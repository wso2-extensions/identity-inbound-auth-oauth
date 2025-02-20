/*
 * Copyright (c) 2018-2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
public class OAuthClientAuthnServiceTest {

    private static final String CLIENT_ID = "someclientid";
    private static final String CLIENT_SECRET = "someclientsecret";

    private OAuthClientAuthnService oAuthClientAuthnService = new OAuthClientAuthnService();
    private BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
    private SampleClientAuthenticator sampleClientAuthenticator = new SampleClientAuthenticator();

    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        identityUtil = mockStatic(IdentityUtil.class);
        identityUtil.when(IdentityUtil::getIdentityConfigDirPath)
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");
        identityUtil.when(() -> IdentityUtil.getPropertyAsList(anyString()))
                .thenReturn(Arrays.asList("private_key_jwt"));

        OAuth2ServiceComponentHolder.addAuthenticationHandler(basicAuthClientAuthenticator);
        OAuth2ServiceComponentHolder.addAuthenticationHandler(sampleClientAuthenticator);
        sampleClientAuthenticator.enabled = true;
    }


    @AfterMethod
    public void cleanup() {

        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(basicAuthClientAuthenticator);
        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(sampleClientAuthenticator);
        identityUtil.close();
    }

    @Test
    public void testGetClientAuthenticators() throws Exception {

        assertEquals(2, oAuthClientAuthnService.getClientAuthenticators().size());
    }

    @DataProvider(name = "testAuthenticateClientData")
    public Object[][] testAuthenticateClientData() {

        Map<String, String> headersWithClientIDandSecret = new HashMap<>();
        headersWithClientIDandSecret.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(CLIENT_ID, CLIENT_SECRET, null));

        Map<String, String> headerWithClientId = new HashMap<>();
        headerWithClientId.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(CLIENT_ID, null, null));

        Map<String, String> headersClientSecret = new HashMap<>();
        headersClientSecret.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(null, CLIENT_SECRET, null));

        Map<String, String> headersWithMultipleCreds = new HashMap<>();
        headersWithMultipleCreds.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(CLIENT_ID, CLIENT_SECRET, null));
        headersWithMultipleCreds.put(SampleClientAuthenticator.SAMPLE_HEADER, CLIENT_ID);

        return new Object[][]{

                // Correct authorization header present with correct encoding for basic auth.
                {headersWithClientIDandSecret, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID, false, true,
                        null},

                // Only client id is present with correct encoding for basic auth.
                {headerWithClientId, new HashMap<String, List>(), false, true, "invalid_client", 0, null, false, true,
                        "Client ID not found in the request."},

                // Only client secret is present with correct encoding for basic auth.
                {headersClientSecret, new HashMap<String, List>(), false, true, "invalid_client", 0, null, false, true,
                        "Client ID not found in the request."},

                // Multiple authenticators are engaged since multiple evaluation criteria are met.
                {headersWithMultipleCreds, new HashMap<String, List>(), false, true, "invalid_request", 2, CLIENT_ID,
                        false, true, "The client MUST NOT use more than one authentication method in each"},

                // Multiple authentication criterias are satisfied. But sample authenticator is disabled.
                {headersWithMultipleCreds, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID,
                        true, true, null},

                // Basic authentication fails without exception from BasicClientAuthenticator.
                {headersWithClientIDandSecret, new HashMap<String, List>(), false, false, "invalid_client", 1,
                        CLIENT_ID, false, true, "Client credentials are invalid."},

                // Invalid Client ID and no valid client is present for that Client ID.
                {headersWithClientIDandSecret, new HashMap<String, List>(), false, true, "invalid_client", 0, null,
                        false, false, "Client credentials are invalid."},

        };
    }

    @Test(dataProvider = "testAuthenticateClientData")
    public void testAuthenticateClient(Map<String, String> headers, Map<String, List> bodyParams, boolean
            isAuthenticated, boolean isBasicAuthenticated, String errorCode, int numberOfExecutedAuthenticators,
                                       String clientId, boolean disableSampleAuthenticator, boolean hasAuthAppDO,
                                       String errorMsg) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            if (disableSampleAuthenticator) {
                sampleClientAuthenticator.enabled = false;
            }
            oAuth2Util.when(() -> OAuth2Util.authenticateClient(anyString(), anyString(), anyString())).thenReturn
                    (isBasicAuthenticated);
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
            setHeaders(httpServletRequest, headers);
            oAuth2Util.when(() -> OAuth2Util.isFapiConformantApp(anyString())).thenReturn(false);
            ServiceProvider serviceProvider = new ServiceProvider();
            oAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString())).thenReturn(serviceProvider);
            if (hasAuthAppDO) {
                OAuthAppDO oAuthAppDO = new OAuthAppDO();
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenReturn(oAuthAppDO);
            } else {
                oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                        .thenThrow(new InvalidOAuthClientException("application.not.found"));
            }
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
            OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient
                    (httpServletRequest, bodyParams);
            assertEquals(oAuthClientAuthnContext.isAuthenticated(), isAuthenticated);
            assertEquals(oAuthClientAuthnContext.getErrorCode(), errorCode);
            assertEquals(oAuthClientAuthnContext.getErrorMessage(), errorMsg);
            assertEquals(oAuthClientAuthnContext.getExecutedAuthenticators().size(), numberOfExecutedAuthenticators);
            assertEquals(oAuthClientAuthnContext.getClientId(), clientId);
        }
    }

    private void setHeaders(HttpServletRequest request, Map<String, String> headers) {

        headers.forEach((key, value) ->
                when(request.getHeader(key)).thenReturn(value)
        );
    }

    @Test
    public void testAuthenticateForFapiApplicationsWithInvalidAuthenticatorsRegistered() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            HashMap<String, List> bodyParams = new HashMap<>();
            bodyParams.put(OAuth.OAUTH_CLIENT_ID, Arrays.asList(CLIENT_ID));
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setTokenEndpointAuthMethod("private_key_jwt");
            oAuthAppDO.setFapiConformanceEnabled(true);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                    .thenReturn(oAuthAppDO);
            oAuth2Util.when(() -> OAuth2Util.isFapiConformantApp(anyString())).thenReturn(true);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
            OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient
                    (httpServletRequest, bodyParams);
            assertEquals(oAuthClientAuthnContext.isAuthenticated(), false);
            assertEquals(oAuthClientAuthnContext.getErrorCode(), "invalid_request");
            assertEquals(oAuthClientAuthnContext.getExecutedAuthenticators().size(), 0);
        }
    }

    @DataProvider(name = "testDataForAuthMethodConfiguredInApp")
    public Object[][] testDataForAuthMethodConfiguredInApp() {

        return new Object[][]{
                // Authentication method configured for FAPI conformant application.
                {true},
                // Authentication method configured for non-FAPI application.
                {false}
        };
    }

    @Test(dataProvider = "testDataForAuthMethodConfiguredInApp")
    public void testAuthenticateWhenAuthMethodConfiguredInApp(boolean isFapiApp) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            HashMap<String, List> bodyParams = new HashMap<>();
            bodyParams.put(OAuth.OAUTH_CLIENT_ID, Arrays.asList(CLIENT_ID));
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setTokenEndpointAuthMethod("private_key_jwt");
            oAuthAppDO.setFapiConformanceEnabled(isFapiApp);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()))
                    .thenReturn(oAuthAppDO);
            oAuth2Util.when(() -> OAuth2Util.isFapiConformantApp(anyString())).thenReturn(true);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
            OAuthClientAuthenticator oAuthClientAuthenticator = mock(OAuthClientAuthenticator.class);
            when(oAuthClientAuthenticator.getName()).thenReturn("PrivateKeyJWTClientAuthenticator");
            when(oAuthClientAuthenticator.isEnabled()).thenReturn(true);
            when(oAuthClientAuthenticator.canAuthenticate(Mockito.any(), Mockito.any(), Mockito.any()))
                    .thenReturn(true);
            when(oAuthClientAuthenticator.authenticateClient(Mockito.any(), Mockito.any(), Mockito.any()))
                    .thenReturn(true);
            when(oAuthClientAuthenticator.getClientId(Mockito.any(), Mockito.any(), Mockito.any()))
                    .thenReturn(CLIENT_ID);
            when(oAuthClientAuthenticator.getSupportedClientAuthenticationMethods())
                    .thenReturn(
                            Arrays.asList(new ClientAuthenticationMethodModel("private_key_jwt", "Private Key JWT")));
            OAuthClientAuthnService oAuthClientAuthnService = Mockito.spy(OAuthClientAuthnService.class);
            when(oAuthClientAuthnService.getClientAuthenticators()).thenReturn
                    (Arrays.asList(oAuthClientAuthenticator));
            OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient
                    (httpServletRequest, bodyParams);
            assertEquals(oAuthClientAuthnContext.isAuthenticated(), true);
            assertEquals(oAuthClientAuthnContext.getErrorCode(), null);
            assertEquals(oAuthClientAuthnContext.getExecutedAuthenticators().size(), 1);
        }
    }
}
