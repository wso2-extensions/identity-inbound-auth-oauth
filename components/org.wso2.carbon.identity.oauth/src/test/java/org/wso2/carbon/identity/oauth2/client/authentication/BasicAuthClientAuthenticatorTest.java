/*
 * Copyright (c) 2018-2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
public class BasicAuthClientAuthenticatorTest {

    private BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
    private static final String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static final String CLIENT_ID = "someclientid";
    private static final String CLIENT_SECRET = "someclientsecret";
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeMethod
    public void setUp() {
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
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
    }

    @Test
    public void testGetPriority() throws Exception {

        assertEquals(100, basicAuthClientAuthenticator.getPriority(),
                "Default priority of the basic authenticator has changed");
    }

    @DataProvider(name = "testClientAuthnData")
    public Object[][] testClientAuthnData() {

        return new Object[][]{

                // Correct authorization header present with correct encoding
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null),
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID, CLIENT_SECRET), true,
                        true},

                // Correct authentication information is in headers and no information in context.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null),
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(null, null), false,
                        false},
        };
    }

    @Test(dataProvider = "testClientAuthnData")
    public void testAuthenticateClient(String headerName, String headerValue, HashMap<String, List> bodyContent,
                                       Object oAuthClientAuthnContextObj, boolean isAuthenticated,
                                       boolean authenticationResult) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

            oAuth2Util.when(() -> OAuth2Util.authenticateClient(anyString(), anyString(), anyString())).thenReturn
                    (isAuthenticated);
            when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
            assertEquals(basicAuthClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                    oAuthClientAuthnContext), authenticationResult, "Expected client authentication result was not " +
                    "received");
        }
    }

    @DataProvider(name = "testClientAuthnDataErrorScenario")
    public Object[][] testClientAuthnDataErrorScenario() {

        return new Object[][]{
                // Throws an IdentityOAuthAdminException
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null),
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID, CLIENT_SECRET), new
                        IdentityOAuthAdminException("OAuth Admin Error")},

                // Throws an IdentityOAuthAdminException
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null),
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID, CLIENT_SECRET), new
                        IdentityOAuthAdminException("OAuth Admin Error")},

                // Throws an IdentityOAuthAdminException
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null),
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID, CLIENT_SECRET), new
                        IdentityOAuth2Exception("OAuth Admin Error")},
        };
    }

    @Test(dataProvider = "testClientAuthnDataErrorScenario", expectedExceptions = OAuthClientAuthnException.class)
    public void testAuthenticateClientExeption(String headerName, String headerValue, HashMap<String, List> bodyContent,
                                               Object oAuthClientAuthnContextObj, Object exception) throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
            HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

            if (exception instanceof IdentityOAuthAdminException) {
                oAuth2Util.when(() -> OAuth2Util.authenticateClient(anyString(), anyString(), anyString())).thenThrow(
                        (IdentityOAuthAdminException) exception);
            } else if (exception instanceof IdentityOAuth2Exception) {
                oAuth2Util.when(() -> OAuth2Util.authenticateClient(anyString(), anyString(), anyString())).thenThrow(
                        (IdentityOAuth2Exception) exception);
            }

            when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
            basicAuthClientAuthenticator.authenticateClient(httpServletRequest, bodyContent, oAuthClientAuthnContext);
        }
    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                // Correct Authorization header with valid client id and secret.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true},

                // Simple case correct authorization header with valid client id and secret.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true},

                // Simple case authorization header value without "Basic" prefix
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Gibberish value without Basic part", new HashMap<String, List>(),
                        false},

                // Simple case authorization header value with "Basic" prefix.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Basic Gibberish value with Basic part", new HashMap<String, List>(),
                        true},

                // Simple authorization header with null value.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, new HashMap<String, List>(), false},

                // Simple authorization header but no value. But has client id and secret in body.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID,
                        CLIENT_SECRET), true},

                // No authorization header. but client id and secret present in the body.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), true},

                // No authorization header. Only client secret is present in body.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, CLIENT_SECRET), false},

                // No authorization header. Only client id is present in the body.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, null), false},

                // Neither authorization header nor body parameters present with client id and secret.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, null), false},
        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(String headerName, String headerValue, HashMap<String, List> bodyContent, boolean
            canHandle) throws Exception {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        assertEquals(basicAuthClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @Test
    public void testGetName() throws Exception {

        assertEquals("BasicOAuthClientCredAuthenticator", basicAuthClientAuthenticator.getName(), "Basic " +
                "OAuth client authenticator name has changed.");
    }

    @DataProvider(name = "testGetClientIdData")
    public Object[][] testGetClientIdData() {

        return new Object[][]{

                // Correct authorization header present with correct encoding
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null)
                        , new HashMap<String, List>(), CLIENT_ID},

                // Simple case authorization header with correct client id and secret
                {SIMPLE_CASE_AUTHORIZATION_HEADER, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), CLIENT_ID},

                // Simple case authorization header with null value. But has client id and secret in body content.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID,
                        CLIENT_SECRET), CLIENT_ID},

                // No authorization header. But has client id and secret in body.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), CLIENT_ID},
        };
    }

    @Test(dataProvider = "testGetClientIdData")
    public void testGetClientId(String headerName, String headerValue, HashMap<String, List> bodyContent, String
            clientId) throws Exception {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        assertEquals(basicAuthClientAuthenticator.getClientId(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), clientId);
    }

    @DataProvider(name = "testGetClientIdDataErrorScenario")
    public Object[][] testGetClientIdDataErrorScenario() {

        return new Object[][]{

                // Authorization header with only client secret base64 encoded.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(null,
                        CLIENT_SECRET, null), new HashMap<String, List>()},

                // Simple case authorization header with only client id base64 encoded.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID, null,
                        null), new
                        HashMap<String, List>()},

                // Authorization header present with correct id and secret encoding. Body also has client id and secret.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID,
                        CLIENT_SECRET)},
        };
    }

    @Test(dataProvider = "testGetClientIdDataErrorScenario", expectedExceptions = OAuthClientAuthnException.class)
    public void testGetClientIdErrorScenario(String headerName, String headerValue, HashMap<String, List> bodyContent)
            throws Exception {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        basicAuthClientAuthenticator.getClientId(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext());
    }

    @Test
    public void testGetSupportedClientAuthenticationMethods() {

        List<String> supportedAuthMethods = new ArrayList<>();
        for (ClientAuthenticationMethodModel clientAuthenticationMethodModel : basicAuthClientAuthenticator
                .getSupportedClientAuthenticationMethods()) {
            supportedAuthMethods.add(clientAuthenticationMethodModel.getName());
        }
        Assert.assertTrue(supportedAuthMethods.contains("client_secret_basic"));
        Assert.assertTrue(supportedAuthMethods.contains("client_secret_post"));
        assertEquals(supportedAuthMethods.size(), 2);
    }

    private OAuthClientAuthnContext buildOAuthClientAuthnContext(String clientId, String clientSecret) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        if (StringUtils.isNotEmpty(clientSecret)) {
            oAuthClientAuthnContext.addParameter(OAuth.OAUTH_CLIENT_SECRET, clientSecret);
        }
        return oAuthClientAuthnContext;
    }
}
