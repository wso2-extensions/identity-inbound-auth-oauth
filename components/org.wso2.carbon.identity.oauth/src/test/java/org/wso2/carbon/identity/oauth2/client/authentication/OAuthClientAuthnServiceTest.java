/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

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
public class OAuthClientAuthnServiceTest extends PowerMockIdentityBaseTest {

    private static String CLIENT_ID = "someclientid";
    private static String CLIENT_SECRET = "someclientsecret";

    OAuthClientAuthnService oAuthClientAuthnService = new OAuthClientAuthnService();
    BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
    SampleClientAuthenticator sampleClientAuthenticator = new SampleClientAuthenticator();

    @BeforeMethod
    public void setUp() throws Exception {

        OAuth2ServiceComponentHolder.addAuthenticationHandler(basicAuthClientAuthenticator);
        OAuth2ServiceComponentHolder.addAuthenticationHandler(sampleClientAuthenticator);
        sampleClientAuthenticator.enabled = true;
    }

    @AfterMethod
    public void cleanup() {

        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(basicAuthClientAuthenticator);
        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(sampleClientAuthenticator);
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
                {headersWithClientIDandSecret, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID, false},

                // Only client id is present with correct encoding for basic auth.
                {headerWithClientId, new HashMap<String, List>(), false, true, "invalid_request", 1, null, false},

                // Only client secret is present with correct encoding for basic auth.
                {headersClientSecret, new HashMap<String, List>(), false, true, "invalid_request", 1, null, false},

                // Multiple authenticators are engaged since multiple evaluation criteria are met.
                {headersWithMultipleCreds, new HashMap<String, List>(), false, true, "invalid_request", 2, CLIENT_ID,
                        false},

                // Multiple authentication criterias are satisfied. But sample authenticator is disabled.
                {headersWithMultipleCreds, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID,
                        true},

                // Basic authentication fails without exception from BasicClientAuthenticator.
                {headersWithClientIDandSecret, new HashMap<String, List>(), false, false, "invalid_client", 1, CLIENT_ID,
                        false},

        };
    }

    @Test(dataProvider = "testAuthenticateClientData")
    public void testAuthenticateClient(Map<String, String> headers, Map<String, List> bodyParams, boolean
            isAuthenticated, boolean isBasicAuthenticated, String errorCode, int numberOfExecutedAuthenticators,
                                       String clientId, boolean disableSampleAuthenticator) throws Exception {

        if (disableSampleAuthenticator) {
            sampleClientAuthenticator.enabled = false;
        }
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.authenticateClient(Matchers.anyString(), Matchers.anyString())).thenReturn
                (isBasicAuthenticated);
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        setHeaders(httpServletRequest, headers);
        OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient
                (httpServletRequest, bodyParams);
        assertEquals(oAuthClientAuthnContext.isAuthenticated(), isAuthenticated);
        assertEquals(oAuthClientAuthnContext.getErrorCode(), errorCode);
        assertEquals(oAuthClientAuthnContext.getExecutedAuthenticators().size(), numberOfExecutedAuthenticators);
        assertEquals(oAuthClientAuthnContext.getClientId(), clientId);
    }

    private void addAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator) {

        OAuth2ServiceComponentHolder.addAuthenticationHandler(oAuthClientAuthenticator);
    }

    private void removeAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator) {

        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(oAuthClientAuthenticator);
    }

    private void setHeaders(HttpServletRequest request, Map<String, String> headers) {

        headers.forEach((key, value) ->
                PowerMockito.when(request.getHeader(key)).thenReturn(value)
        );
    }
}
