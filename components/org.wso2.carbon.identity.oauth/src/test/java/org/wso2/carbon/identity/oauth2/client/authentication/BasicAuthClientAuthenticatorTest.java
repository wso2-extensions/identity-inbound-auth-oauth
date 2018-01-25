/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.testng.Assert.assertEquals;

@PrepareForTest({
        HttpServletRequest.class,
        OAuth2Util.class
})
@WithCarbonHome
public class BasicAuthClientAuthenticatorTest extends PowerMockIdentityBaseTest {

    private BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
    private static String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static String CLIENT_ID = "someclientid";
    private static String CLIENT_SECRET = "someclientsecret";

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
                        new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID, CLIENT_SECRET), true, true},

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

        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.authenticateClient(Matchers.anyString(), Matchers.anyString())).thenReturn
                (isAuthenticated);
        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        assertEquals(basicAuthClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                oAuthClientAuthnContext), authenticationResult, "Expected client authentication result was not " +
                "received");
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

        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.mockStatic(OAuth2Util.class);

        if (exception instanceof IdentityOAuthAdminException) {
            PowerMockito.when(OAuth2Util.authenticateClient(Matchers.anyString(), Matchers.anyString())).thenThrow(
                    (IdentityOAuthAdminException) exception);
        } else if (exception instanceof IdentityOAuth2Exception) {
            PowerMockito.when(OAuth2Util.authenticateClient(Matchers.anyString(), Matchers.anyString())).thenThrow(
                    (IdentityOAuth2Exception) exception);
        }

        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        basicAuthClientAuthenticator.authenticateClient(httpServletRequest, bodyContent, oAuthClientAuthnContext);
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

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
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

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
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

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        basicAuthClientAuthenticator.getClientId(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext());
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
