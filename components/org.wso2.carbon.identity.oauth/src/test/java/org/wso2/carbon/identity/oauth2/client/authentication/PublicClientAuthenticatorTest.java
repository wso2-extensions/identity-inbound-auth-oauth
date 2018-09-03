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

import org.apache.axis2.transport.http.HTTPConstants;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.List;

import static org.testng.Assert.assertEquals;

@PrepareForTest({
        HttpServletRequest.class,
        OAuth2Util.class
})
@WithCarbonHome
public class PublicClientAuthenticatorTest extends PowerMockIdentityBaseTest {

    private PublicClientAuthenticator publicClientAuthenticator = new PublicClientAuthenticator();
    private static String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static String CLIENT_ID = "someclientid";
    private static String CLIENT_SECRET = "someclientsecret";

    @Test
    public void testGetPriority() {

        assertEquals(200, publicClientAuthenticator.getPriority(),
                "Default priority of the public client authenticator has changed");
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(String headerName, String headerValue, HashMap<String, List> bodyContent,
                                    boolean publicClient, boolean canHandle) throws Exception {

        PowerMockito.mockStatic(OAuth2Util.class);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setBypassClientCredentials(publicClient);

        PowerMockito.when(OAuth2Util.getAppInformationByClientId(CLIENT_ID)).thenReturn(appDO);

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        assertEquals(publicClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                // Correct Authorization header with valid client id and secret. Also a Public client.
                {HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true, false},

                // Simple case correct authorization header with valid client id and secret. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, ClientAuthUtil.getBase64EncodedBasicAuthHeader(CLIENT_ID,
                        CLIENT_SECRET, null), new HashMap<String, List>(), true, false},

                // Simple case authorization header value without "Basic" prefix. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Some value without Basic part", new HashMap<String, List>(),
                        true, false},

                // Simple case authorization header value with "Basic" prefix. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, "Basic some value with Basic part", new HashMap<String, List>(),
                        true, false},

                // Simple authorization header with null value. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, new HashMap<String, List>(), true, false},

                // Simple authorization header but no value. But has client id and secret in body. Also a Public client.
                {SIMPLE_CASE_AUTHORIZATION_HEADER, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID,
                        CLIENT_SECRET), true, true},

                // No authorization header. but client id and secret present in the body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), true, true},

                // No authorization header. but client id and secret present in the body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, CLIENT_SECRET), false, false},

                // No authorization header. Only client secret is present in body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, CLIENT_SECRET),
                        true, false},

                // No authorization header. Only client secret is present in body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, CLIENT_SECRET),
                        false, false},

                // No authorization header. Only client id is present in the body and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, null), true, true},

                // No authorization header. Only client id is present in the body and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(CLIENT_ID, null), false, false},

                // Neither authorization header nor body parameters present and a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, null),
                        true, false},

                // Neither authorization header nor body parameters present and not a public client.
                {null, null, ClientAuthUtil.getBodyContentWithClientAndSecret(null, null), false, false},
        };
    }

}
