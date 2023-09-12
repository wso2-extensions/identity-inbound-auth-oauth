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
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.io.File;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({
        HttpServletRequest.class,
        OAuth2Util.class,
        IdentityUtil.class
})
@WithCarbonHome
public class OAuthClientAuthnServiceTest extends PowerMockIdentityBaseTest {

    private static final String CLIENT_ID = "someclientid";
    private static final String CLIENT_SECRET = "someclientsecret";
    private static final String CLIENT_ASSERTION = "eyJraWQiOiJqeVJVY3l0MWtWQ2xjSXZsVWxjRHVrVlozdFUiLCJhbGciOiJQUzI1" +
            "NiJ9.eyJzdWIiOiJpWXBSbTY0YjJ2bXZtS0RoZEw2S1pEOXo2ZmNhIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0a" +
            "DIvdG9rZW4iLCJpc3MiOiJpWXBSbTY0YjJ2bXZtS0RoZEw2S1pEOXo2ZmNhIiwiZXhwIjoxNjEwNjMxNDEyLCJpYXQiOjE2MTA2MDE" +
            "0MTIsImp0aSI6IjE2MTA2MDE0MTI5MDAifQ.tmMTlCL-VABhFTA6QQ6UPvUydKuzynidepAa8oZGEBfVyAsiW5IF01NKYD0ynpXXJC" +
            "Q6hcbWK0FEGity67p6DeI9LT-xAnaKwZY7H8rbuxWye2vhanM0jVa1vggsmwWYyOR4k55ety9lP1MkcGZpaK48qoaqsX_X7GCSGXzq" +
            "BncTEPYfCpVUQtS4ctwoCl06TFbY2Lfm9E24z1rfmU9xPc7au6LpKRLMMHQ8QXuc-FhnWdgEFv_3tAai2ovVmrqEfwj6Z6Ew5bFeI9" +
            "jtCR4TSol47hzDwldx5rH7m2OPUx66yEtGrM7UU62fC-4nxplZ69fjlHN4KQ62PxEaCQs0_A";
    private static final String CERTIFICATE_CONTENT = "-----BEGIN CERTIFICATE-----MIID3" +
            "TCCAsWgAwIBAgIUJQW8iwYsAbyjc/oHti8DPLJH5ZcwDQYJKoZIhvcNAQELBQAwfjELMA" +
            "kGA1UEBhMCU0wxEDAOBgNVBAgMB1dlc3Rlcm4xEDAOBgNVBAcMB0NvbG9tYm8xDTALBgN" +
            "VBAoMBFdTTzIxDDAKBgNVBAsMA0lBTTENMAsGA1UEAwwER2FnYTEfMB0GCSqGSIb3DQEJ" +
            "ARYQZ2FuZ2FuaUB3c28yLmNvbTAeFw0yMDAzMjQxMjQyMDFaFw0zMDAzMjIxMjQyMDFaM" +
            "H4xCzAJBgNVBAYTAlNMMRAwDgYDVQQIDAdXZXN0ZXJuMRAwDgYDVQQHDAdDb2xvbWJvMQ" +
            "0wCwYDVQQKDARXU08yMQwwCgYDVQQLDANJQU0xDTALBgNVBAMMBEdhZ2ExHzAdBgkqhki" +
            "G9w0BCQEWEGdhbmdhbmlAd3NvMi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
            "AoIBAQC+reCEYOn2lnWgFsp0TF0R1wQiD9C/N+dnv4xCa0rFiu4njDzWR/8tYFl0koaxX" +
            "oP0+oGnT07KlkA66q0ztwikLZXphLdCBbJ1hSmNvor48FuSb6DgqWixrUa2LHlpaaV7Rv" +
            "lmG+IhZEgKDXdS+/tK0hlcgRzENyOEdETDO5fFlKGGuwaGv6/w69h2LTKGu5nyDLF51rj" +
            "Q18xp026btHC7se/XSlcp3X63xeOIcFv6m84AN2lnV+g8MOfu2wgWtsKaxn4BL64E7nHZ" +
            "NNLxMRf7GtUm2bl9ydFX4aD1r1Oj4iqFWMNcfQ676Qshk8s7ui3LKWFXwNN/SRD0c/ORt" +
            "v23AgMBAAGjUzBRMB0GA1UdDgQWBBRDu/vqRafReh4fFHS3Nz4T6u9mUDAfBgNVHSMEGD" +
            "AWgBRDu/vqRafReh4fFHS3Nz4T6u9mUDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQE" +
            "BCwUAA4IBAQB7NH51Yj4moEhMonnLUh3eTtf6DUnrpscx6td28rryoDZPfCkJs4VHU9F5" +
            "0etw54FoHqoIaHp5UIB6l1OsVXytUmwrdxbqW7nfOItYwN1yV093aI2aOeMQYmS+vrPkS" +
            "kxySP6+wGCWe4gfMgpr6iu9xiWLpnILw5q71gmXWtS900S5aLbllGYe74jkyldLIdhS4T" +
            "yEBIDgcpZrD8x/Z42al6T/6EANMpvu4Jopisg+uwwkEGSM1I/kjiW+YkWC4oTZ1jMZUWC" +
            "11WbcouLwjfaf6gt4zWitYCP0r0fLGk4bSJfUFsnJNu6vDhx60TbRhIh9P2jxkmgNYPuA" +
            "xFtF8v+h-----END CERTIFICATE-----";

    private OAuthClientAuthnService oAuthClientAuthnService = new OAuthClientAuthnService();
    private BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
    private SampleClientAuthenticator sampleClientAuthenticator = new SampleClientAuthenticator();

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityConfigDirPath())
                .thenReturn(System.getProperty("user.dir")
                        + File.separator + "src"
                        + File.separator + "test"
                        + File.separator + "resources"
                        + File.separator + "conf");

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
                {headerWithClientId, new HashMap<String, List>(), false, true, "invalid_client", 1, null, false},

                // Only client secret is present with correct encoding for basic auth.
                {headersClientSecret, new HashMap<String, List>(), false, true, "invalid_client", 1, null, false},

                // Multiple authenticators are engaged since multiple evaluation criteria are met.
                {headersWithMultipleCreds, new HashMap<String, List>(), false, true, "invalid_request", 2, CLIENT_ID,
                        false},

                // Multiple authentication criterias are satisfied. But sample authenticator is disabled.
                {headersWithMultipleCreds, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID,
                        true},

                // Basic authentication fails without exception from BasicClientAuthenticator.
                {headersWithClientIDandSecret, new HashMap<String, List>(), false, false, "invalid_client", 1,
                        CLIENT_ID, false},

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
        when(httpServletRequest.getParameter(OAuth.OAUTH_CLIENT_ID)).thenReturn(CLIENT_ID);
        PowerMockito.when(OAuth2Util.isFapiConformantApp(Mockito.anyString())).thenReturn(false);
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

    @DataProvider(name = "testAuthenticateClientDataForFAPI")
    public Object[][] testAuthenticateClientDataForFAPI() {

        Map<String, String> headersWithCert = new HashMap<>();
        headersWithCert.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(CLIENT_ID, CLIENT_SECRET, null));
        headersWithCert.put("x-wso2-mtls-cert", CERTIFICATE_CONTENT);

        Map<String, String> headersWithoutCert = new HashMap<>();
        headersWithoutCert.put(HTTPConstants.HEADER_AUTHORIZATION, ClientAuthUtil
                .getBase64EncodedBasicAuthHeader(CLIENT_ID, CLIENT_SECRET, null));

        return new Object[][]{

                // TLS certificate is passed in the request
                {headersWithCert, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID, false,
                        OAuthConstants.PRIVATE_KEY_JWT, true},

                // TLS certificate is not passed in the request
                {headersWithoutCert, new HashMap<String, List>(), false, true, "invalid_request", 0, null, false,
                        OAuthConstants.PRIVATE_KEY_JWT, false},

                // Registered client authentication method matching the request client authentication method
                {headersWithCert, new HashMap<String, List>(), true, true, null, 1, CLIENT_ID, false,
                        OAuthConstants.PRIVATE_KEY_JWT, true},

                // Registered client authentication method not matching the request client authentication method
                {headersWithCert, new HashMap<String, List>(), false, true, "invalid_request", 0, null, false,
                        OAuthConstants.TLS_CLIENT_AUTH, true}

        };
    }

    @Test(dataProvider = "testAuthenticateClientDataForFAPI")
    public void testAuthenticateForFapiApplications(Map<String, String> headers, Map<String, List> bodyParams,
                                                           boolean isAuthenticated, boolean isBasicAuthenticated,
                                                           String errorCode, int numberOfExecutedAuthenticators,
                                                           String clientId, boolean disableSampleAuthenticator,
                                                           String authMethod, boolean isMTLSEnforced) throws Exception {

        if (disableSampleAuthenticator) {
            sampleClientAuthenticator.enabled = false;
        }
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn
                (isBasicAuthenticated);
        X509Certificate x509Certificate = Mockito.mock(X509Certificate.class);
        if (isMTLSEnforced) {
            PowerMockito.when(OAuth2Util.parseCertificate(Mockito.anyString())).thenReturn(x509Certificate);
        } else {
            PowerMockito.when(OAuth2Util.parseCertificate(Mockito.anyString())).thenReturn(null);
        }
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        when(httpServletRequest.getParameter(OAuth.OAUTH_CLIENT_ID)).thenReturn(clientId);
        when(httpServletRequest.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION)).thenReturn(CLIENT_ASSERTION);
        when(httpServletRequest.getParameter(OAuthConstants.OAUTH_JWT_ASSERTION_TYPE))
                .thenReturn(OAuthConstants.OAUTH_JWT_BEARER_GRANT_TYPE);
        setHeaders(httpServletRequest, headers);
        when(IdentityUtil.getProperty(OAuthConstants.MTLS_AUTH_HEADER)).thenReturn("x-wso2-mtls-cert");
        ServiceProvider serviceProvider = new ServiceProvider();
        ServiceProviderProperty authMethodSpProperty = new ServiceProviderProperty();
        authMethodSpProperty.setName(OAuthConstants.TOKEN_ENDPOINT_AUTH_METHOD);
        authMethodSpProperty.setValue(authMethod);
        ServiceProviderProperty fapiAppSpProperty = new ServiceProviderProperty();
        fapiAppSpProperty.setName(OAuthConstants.IS_FAPI_CONFORMANT_APP);
        fapiAppSpProperty.setValue("true");
        serviceProvider.setSpProperties(new ServiceProviderProperty[]{authMethodSpProperty, fapiAppSpProperty});
        PowerMockito.when(OAuth2Util.getServiceProvider(Mockito.anyString())).thenReturn(serviceProvider);
        PowerMockito.when(OAuth2Util.isFapiConformantApp(Mockito.anyString())).thenReturn(true);
        OAuthClientAuthnContext oAuthClientAuthnContext = oAuthClientAuthnService.authenticateClient
                (httpServletRequest, bodyParams);
        assertEquals(oAuthClientAuthnContext.isAuthenticated(), isAuthenticated);
        assertEquals(oAuthClientAuthnContext.getErrorCode(), errorCode);
        assertEquals(oAuthClientAuthnContext.getExecutedAuthenticators().size(), numberOfExecutedAuthenticators);
        assertEquals(oAuthClientAuthnContext.getClientId(), clientId);
    }
}
