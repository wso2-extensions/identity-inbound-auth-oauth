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
package org.wso2.carbon.identity.oidc.session.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oidc.session.config.OIDCSessionManagementConfiguration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;

/**
 * Unit test coverage for OIDCSessionManagementUtil class.
 * Migrated from PowerMock/PowerMockTestCase to Mockito MockedStatic (Java 21 compatible).
 */
public class OIDCSessionManagementUtilTest {

    @Mock
    OIDCSessionManagementConfiguration oidcSessionManagementConfiguration;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    ServiceURL serviceURL;

    @Mock
    ServiceURLBuilder serviceURLBuilder;

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMock;
    private AutoCloseable mocks;

    private static final String CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String CALLBACK_URL = "http://localhost:8080/playground2/oauth2client";
    private static final String OPBROWSER_STATE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String SESSION_STATE = "18b2343e6edaec1c8b1208169ffa141d158156518135350be60dfbf6f41d340f" +
            ".W2Gf-RAzLUFy2xq_8tuM6A";
    String[] responseType = new String[]{"id_token", "token", "code"};

    @BeforeMethod
    public void setUp() throws Exception {

        mocks = MockitoAnnotations.openMocks(this);
        oAuthServerConfigurationMock = Mockito.mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfigurationMock.when(OAuthServerConfiguration::getInstance).thenReturn(oAuthServerConfiguration);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        oAuthServerConfigurationMock.close();
        mocks.close();
    }

    @Test
    public void testGetSessionStateParam() {

        String state = OIDCSessionManagementUtil.getSessionStateParam(CLIENT_ID, CALLBACK_URL, OPBROWSER_STATE);
        Assert.assertNotNull(state, "This is empty");
    }

    @DataProvider(name = "provideDataFortestAddSessionStateToURL")
    public Object[][] provideDataFortestAddSessionStateToURL() {

        String url1 = "http://localhost:8080/playground2/oauth2client#id_token" +
                "=eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNek" +
                "V6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXST" +
                "RORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyJ1NUZJZkc1eHpMdkJH" +
                "aWFtb0FZenpjcXBCcWdhIl0sImF6cCI6InU1RklmRzV4ekx2QkdpYW1vQVl6emNxcEJxZ2EiLCJpc3MiOiJodHRwczpcL1w" +
                "vbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE1MDc1NDUzNjksIm5vbmNlIjoiQ3FzVTl3WmxRSVlHVU" +
                "I4NiIsImlhdCI6MTUwNzU0MTc2OSwic2lkIjoiMzkxNTdlNzItMDM0OS00ZTNlLWEzMjEtODNmODI5MGY1NjliIn0.NvU_l" +
                "1sXegyWTOaicDIxeR-YLLaIWNVvpsNl8GHIQv3Z7QoZOug3qtl6AnSPycAcAmZ7VmELGcNlRlKWT63lOBRpZTrvuEP3RGlpd" +
                "m9iieq5HnrpTdaIuAM1kc6ErYMI48Cwi_r6inaTI_E5KuniQ5YoF5q4hm511oZ1MaELCnRYEp-UPp8Rhu2Pv0MIccuaczkg" +
                "Pw0ela07bfLoP_rH03Tdjt9WcxDBNFoaT_ksZhyuKqK5jHSN_DjMfAe2NH9VK3VGMx1ujXbhj_Non9yN5E-Ndrx_5sfJYPj" +
                "zRri9Cx_yV4Hv7I8p_jMQucN290mtLXrB5DmYSO4Ga-tuouFUkw";
        String actual1 = url1 + "&" + "session_state" + "=" + SESSION_STATE;

        String url2 = "http://localhost:8080/playground2/oauth2client";
        String actual2 = url2 + "#" + "session_state" + "=" + SESSION_STATE;

        String url3 = "http://localhost:8080/playground2/oauth2client?code=37f348e8-6e37-3a49-8b7d-64cfcf8e8ed0";
        String actual3 = url3 + "&" + "session_state" + "=" + SESSION_STATE;

        String actual4 = url2 + "?" + "session_state" + "=" + SESSION_STATE;

        return new Object[][]{
                {url1, SESSION_STATE, responseType[0], actual1},
                {url2, "", responseType[2], url2},
                {"", "", responseType[2], ""},
                {url1, SESSION_STATE, responseType[0], actual1},
                {url2, SESSION_STATE, responseType[0], actual2},
                {url3, SESSION_STATE, responseType[2], actual3},
                {url2, SESSION_STATE, responseType[2], actual4},
                {url2, "", responseType[2], url2}
        };
    }

    @Test(dataProvider = "provideDataFortestAddSessionStateToURL")
    public void testAddSessionStateToURL(String url, String sessionState, String responseType, String actual) {

        String urlReturned = OIDCSessionManagementUtil.addSessionStateToURL(url, sessionState, responseType);
        Assert.assertEquals(urlReturned, actual, "Invalid returned value");
    }

    @DataProvider(name = "provideDataForTestAddSessionStateToURL1")
    public Object[][] provideDataForTestAddSessionStateToURL1() {

        String url = "http://localhost:8080/playground2/oauth2client#id_token" +
                "=eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNek" +
                "V6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXST" +
                "RORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyJ1NUZJZkc1eHpMdkJH" +
                "aWFtb0FZenpjcXBCcWdhIl0sImF6cCI6InU1RklmRzV4ekx2QkdpYW1vQVl6emNxcEJxZ2EiLCJpc3MiOiJodHRwczpcL1w" +
                "vbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE1MDc1NDUzNjksIm5vbmNlIjoiQ3FzVTl3WmxRSVlHVU" +
                "I4NiIsImlhdCI6MTUwNzU0MTc2OSwic2lkIjoiMzkxNTdlNzItMDM0OS00ZTNlLWEzMjEtODNmODI5MGY1NjliIn0.NvU_l" +
                "1sXegyWTOaicDIxeR-YLLaIWNVvpsNl8GHIQv3Z7QoZOug3qtl6AnSPycAcAmZ7VmELGcNlRlKWT63lOBRpZTrvuEP3RGlpd" +
                "m9iieq5HnrpTdaIuAM1kc6ErYMI48Cwi_r6inaTI_E5KuniQ5YoF5q4hm511oZ1MaELCnRYEp-UPp8Rhu2Pv0MIccuaczkg" +
                "Pw0ela07bfLoP_rH03Tdjt9WcxDBNFoaT_ksZhyuKqK5jHSN_DjMfAe2NH9VK3VGMx1ujXbhj_Non9yN5E-Ndrx_5sfJYPj" +
                "zRri9Cx_yV4Hv7I8p_jMQucN290mtLXrB5DmYSO4Ga-tuouFUkw";
        Cookie opbscookie = new Cookie("obps", OPBROWSER_STATE);

        return new Object[][]{
                {url, opbscookie},
                {url, null}
        };
    }

    @Test(dataProvider = "provideDataForTestAddSessionStateToURL1")
    public void testAddSessionStateToURL1(String url, Object obpscookie) {

        String state = OIDCSessionManagementUtil.addSessionStateToURL(url, CLIENT_ID, CALLBACK_URL, (Cookie) obpscookie,
                responseType[1]);
        Assert.assertNotNull(state, "This is empty");
    }

    @DataProvider(name = "provideDataForTestGetOPBrowserStateCookie")
    public Object[][] provideDataForTestGetOPBrowserStateCookie() {

        Cookie opbscookie = new Cookie("opbs", OPBROWSER_STATE);
        Cookie commonAuth = new Cookie("commonAuth", "eab0-40d2-a46d");
        return new Object[][]{
                {null, null},
                {new Cookie[]{opbscookie}, opbscookie},
                {new Cookie[]{null}, null},
                {new Cookie[]{commonAuth}, null},
                {new Cookie[]{opbscookie}, opbscookie}, {null, null}
        };
    }

    @Test(dataProvider = "provideDataForTestGetOPBrowserStateCookie")
    public void testGetOPBrowserStateCookie(Object[] cookie, Object expectedResult) {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getCookies()).thenReturn((Cookie[]) cookie);
        Assert.assertEquals(OIDCSessionManagementUtil.getOPBrowserStateCookie(request), expectedResult);
    }

    @Test
    public void testAddOPBrowserStateCookie() {

        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Cookie cookie = OIDCSessionManagementUtil.addOPBrowserStateCookie(response);
        Assert.assertNotNull(cookie, "Opbs cookie is null");
    }

    @DataProvider(name = "provideDataForTestRemoveOPBrowserStateCookie")
    public Object[][] provideDataForTestRemoveOPBrowserStateCookie() {

        Cookie opbscookie = new Cookie("opbs", OPBROWSER_STATE);
        Cookie commonAuth = new Cookie("commonAuth", "eab0-40d2-a46d");

        return new Object[][]{
                {new Cookie[]{(opbscookie)}, opbscookie},
                {null, null},
                {new Cookie[]{(opbscookie)}, opbscookie},
                {new Cookie[]{(commonAuth)}, null},
        };
    }

    @Test(dataProvider = "provideDataForTestRemoveOPBrowserStateCookie")
    public void testRemoveOPBrowserStateCookie(Object[] cookie, Object expected) {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getCookies()).thenReturn((Cookie[]) cookie);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        Cookie returnedCookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
        Assert.assertEquals(returnedCookie, expected, "Returned cookie is not equal as expected one");
    }

    @Test
    public void testGetOrigin() {

        String returnedUrl = OIDCSessionManagementUtil.getOrigin(CALLBACK_URL);
        Assert.assertEquals(returnedUrl, "http://localhost:8080", "Returned Url is different from expected url");
    }

    @DataProvider(name = "provideDataForTestGetOIDCLogoutConsentURL")
    public Object[][] provideDataForTestGetOIDCLogoutConsentURL() {

        String[] consentUrl = {"https://localhost:9443/authenticationendpoint/logout_consent.do",
                "https://localhost:9443/authenticationendpoint/oauth2_logout_consent.do"};
        return new Object[][]{
                {consentUrl[0], consentUrl[0]}, {"", consentUrl[1]}
        };
    }

    @Test(dataProvider = "provideDataForTestGetOIDCLogoutConsentURL")
    public void testGetOIDCLogoutConsentURL(String consentUrl, String expectedUrl) throws Exception {

        try (MockedStatic<OIDCSessionManagementConfiguration> configMock =
                     Mockito.mockStatic(OIDCSessionManagementConfiguration.class)) {

            configMock.when(OIDCSessionManagementConfiguration::getInstance)
                    .thenReturn(oidcSessionManagementConfiguration);
            Mockito.when(oidcSessionManagementConfiguration.getOIDCLogoutConsentPageUrl()).thenReturn(consentUrl);

            mockServiceURLBuilder(OAuthConstants.OAuth20Endpoints.OIDC_LOGOUT_CONSENT_EP_URL);

            String returnedUrl = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
            Assert.assertEquals(returnedUrl, expectedUrl, "Consent Url is not same as the Expected Consent Url");
        }
    }

    @DataProvider(name = "provideDataForTestGetOIDCLogoutURL")
    public Object[][] provideDataForTestGetOIDCLogoutURL() {

        String[] logoutPageUrl = {"https://localhost:9443/authenticationendpoint/logout.do",
                "https://localhost:9443/authenticationendpoint/oauth2_logout.do"};
        return new Object[][]{
                {logoutPageUrl[0], logoutPageUrl[0]},
                {"", logoutPageUrl[1]}
        };
    }

    @Test(dataProvider = "provideDataForTestGetOIDCLogoutURL")
    public void testGetOIDCLogoutURL(String logoutPageUrl, String expectedUrl) throws Exception {

        try (MockedStatic<OIDCSessionManagementConfiguration> configMock =
                     Mockito.mockStatic(OIDCSessionManagementConfiguration.class)) {

            configMock.when(OIDCSessionManagementConfiguration::getInstance)
                    .thenReturn(oidcSessionManagementConfiguration);
            Mockito.when(oidcSessionManagementConfiguration.getOIDCLogoutPageUrl()).thenReturn(logoutPageUrl);

            mockServiceURLBuilder(OAuthConstants.OAuth20Endpoints.OIDC_DEFAULT_LOGOUT_RESPONSE_URL);

            String returnedUrl = OIDCSessionManagementUtil.getOIDCLogoutURL();
            Assert.assertEquals(returnedUrl, expectedUrl,
                    "Expected logout page url and actual logout url are different");
        }
    }

    @DataProvider(name = "provideDataForTestGetErrorPageURL")
    public Object[][] provideDataForTestGetErrorPageURL() {

        String[] errorPageUrl = {"https://localhost:9443/authenticationendpoint/error.do",
                "https://localhost:9443/authenticationendpoint/oauth2_error.do"};
        String[] expectedUrl = {"https://localhost:9443/authenticationendpoint/error" +
                ".do?oauthErrorCode=404&oauthErrorMsg=not+found",
                "https://localhost:9443/authenticationendpoint/oauth2_error" +
                        ".do?oauthErrorCode=404&oauthErrorMsg=not+found"};
        return new Object[][]{
                {errorPageUrl[0], expectedUrl[0]},
                {"", expectedUrl[1]}
        };
    }

    @Test(dataProvider = "provideDataForTestGetErrorPageURL")
    public void testGetErrorPageURL(String errorPageUrl, String expectedUrl) throws Exception {

        Mockito.when(oAuthServerConfiguration.getOauth2ErrorPageUrl()).thenReturn(errorPageUrl);
        mockServiceURLBuilder(OAuthConstants.OAuth20Endpoints.OAUTH2_ERROR_EP_URL);

        String returnedErrorPageUrl = OIDCSessionManagementUtil.getErrorPageURL("404", "not found");
        Assert.assertEquals(returnedErrorPageUrl, expectedUrl,
                "Expected error page url and actual url are different");
    }

    @Test
    public void testGetOpenIDConnectSkipeUserConsent() {

        Mockito.when(oAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);

        boolean returned = OIDCSessionManagementUtil.getOpenIDConnectSkipeUserConsent();
        Assert.assertTrue(returned, "Expected value and actual value are different");
    }

    private void mockServiceURLBuilder(String context) throws URLBuilderException {

        // Note: ServiceURLBuilder mock must be opened/closed within the test scope.
        // Since this helper is called from tests that already have OAuthServerConfigurationMock open,
        // we open ServiceURLBuilder mock here and rely on the test's try-with-resources or @AfterMethod
        // to manage it. For simplicity in shared helper, we use a field-level mock opened per-method.
        MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = Mockito.mockStatic(ServiceURLBuilder.class);
        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(serviceURLBuilder);
        Mockito.when(serviceURLBuilder.addPath(any())).thenReturn(serviceURLBuilder);
        Mockito.when(serviceURLBuilder.addFragmentParameter(any(), any())).thenReturn(serviceURLBuilder);
        Mockito.when(serviceURLBuilder.addParameter(any(), any())).thenReturn(serviceURLBuilder);
        Mockito.when(serviceURLBuilder.build()).thenReturn(serviceURL);
        Mockito.when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + context);
        // Register for cleanup at end of test
        serviceURLBuilderMocks = serviceURLBuilderMock;
    }

    // Holds the ServiceURLBuilder mock so it can be closed in @AfterMethod
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMocks;

    @AfterMethod(alwaysRun = true)
    public void closeServiceURLBuilderMock() {
        if (serviceURLBuilderMocks != null) {
            serviceURLBuilderMocks.close();
            serviceURLBuilderMocks = null;
        }
    }

    @Test(dataProvider = "provideDataForTestIsIDTokenEncrypted")
    public void testIsIDTokenEncrypted(String idToken, boolean expectedResult) {

        boolean isIdTokenEncrypted = OIDCSessionManagementUtil.isIDTokenEncrypted(idToken);
        Assert.assertEquals(isIdTokenEncrypted, expectedResult, "Expected value and actual value are different.");
    }

    @DataProvider(name = "provideDataForTestIsIDTokenEncrypted")
    public Object[][] provideDataForTestIsIDTokenEncrypted() {

        String encryptedIdToken =
                "eyJraWQiOiJPVFpsTUdZMk1HRXlPVEExTkdJd01URXpPRFppT0RCa05UTXpZakJqTVdOaE9UbGpaR1pqTldaaFpHRmtPRFEyWX" +
                        "phaE9HRXpZbVF4TTJaa05HWmpZUSIsImVuYyI6IkExMjhHQ00iLCJhbGciOiJSU0EtT0FFUCJ9.ayBFPA_EJHl7W7C9e" +
                        "wu4wQlo4y83DgQdgJZGuHzIAn9k3La30DmRckx7PAdIiZgrm9SPlfd59PMuyEcoYg6FEolV2zirOm1b_J7RH8bAydVP" +
                        "Wv-bBL_vfJKMWZV1vkuWTB-HNCg6drp8iuvpEroNOvn8yFL-NMltzSbGKAzSMikhTNqy2MkI9Ds9Ems3_dpERd6P65X" +
                        "U2hMXILpG5YtqUN1VVtv-oHbWX0ZZEWGxeEjw327d4CfZ77FXUdZbemAo3HTq0QrrEVF7NKVHv8sufGu533Aw_9xRIk" +
                        "L8y9ly_6CerOSeS-1xzAxOgKlA7WSieqpoc9t0QLr5IHnY4Q9_RA.MuP6H_u4IWOx0NhF.aOAy6OrOPQWCvrPnu5fHX" +
                        "gjjf53_dZgSRNco58hIEp007hq-0PT4G4TdrSfGiNGFQX6EizjerQzr0x8sQ_FgZxQds0-KHmrz7rafGb4FuWTml8_L" +
                        "2vXcIY4xjKA56q4DL6jRk1skWbjCCFDO37Z4A0A1SWMeZ5wODq_Qz-1SeLdKxT00FhICtZ598X5dmkbB8liVsnLmu3Q" +
                        "YJNdYNu3KpjHrUL_C35YF_gnAyxFNsFjQiRFSUCnQLxNLkNAEephT_u-SlWFbBd2-g6r7i5IQuGUotgxkcAdIVnAVxf" +
                        "zonzwB4F8Ufhfh7_kxRHq9s7s1mknsqO9O4CzxuUGp7Jvun3tl_CF7p6Mq6ltOEcC9ovUoEfTRvrvmmznnYwefDJqcw" +
                        "fyq4eTsRqcfiyzWUXN79-n5RyKDWMlJfXJjusbg9qSCSnr9kYVrcgc.jdK3PVSdSYU-qfnuQCpI5Q";

        String idToken = "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSm" +
                "tPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XS" +
                "TJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJhd" +
                "F9oYXNoIjoiREdLNDRUSVdwM3Noc1hGN3Q3bjlVQSIsImF1ZCI6Ik5pR0ZfRkVDRDFzalRreEZocWlQM0ZQN3pNb2EiLCJjX2hh" +
                "c2giOiJqZi1MMWQwakJBeWRZa3JNNkFsZG13Iiwic3ViIjoiYWRtaW4iLCJuYmYiOjE1OTU1ODA1NzMsImF6cCI6Ik5pR0ZfRkV" +
                "DRDFzalRreEZocWlQM0ZQN3pNb2EiLCJhbXIiOlsiQmFzaWNBdXRoZW50aWNhdG9yIl0sImlzcyI6Imh0dHBzOlwvXC9sb2NhbG" +
                "hvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTU5NTU4NDE3MywiaWF0IjoxNTk1NTgwNTczLCJzaWQiOiI2NTdlMTUxM" +
                "S0yZTkzLTQ2MDAtYjc3NC00ZmNjYTBmMjM2OGQifQ.brA_Dfvrol90ElI2euVFi7PIoRfU7OmFUig7cq1KiTBPtLxCG048PVSaQ" +
                "dUxMXfLuGjaA3qZLykZfViA1fos1ky-afFL5MmYrjdgxJdakxdTO1-5OYvYTpEaUYfPj5twcm38o0C_za55PBxKw1egpKePLmrl" +
                "Kzw_DEXY4KQ815XwNGIZU8F3_LTbKVTQqsjWSfQAdL7_9cB3se37-TkByhml7RBSywUd86eBrTptKN6MaF4jVfALCof1DkWuZMo" +
                "E07Z3q7jpnD1FFye5AjOHDN1v6hppOPypTjcl7CPV0DLiCE8m79SewEFYYSwXBxsKABT58kJQwwPjjYaACSZb2Q";

        String invalidIdToken = "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkd" +
                "SbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00Wl" +
                "RBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYif" +
                "Q.kjcbwecbbcyegkowk_jqnj-jqncjnjcn.eyJhdF9oYXNoIjoiREdLNDRUSVdwM3Noc1hGN3Q3bjlVQSIsImF1ZCI6Ik5pR0Zf" +
                "RkVDRDFzalRreEZocWlQM0ZQN3pNb2EiLCJjX2hhc2giOiJqZi1MMWQwakJBeWRZa3JNNkFsZG13Iiwic3ViIjoiYWRtaW4iLCJ" +
                "uYmYiOjE1OTU1ODA1NzMsImF6cCI6Ik5pR0ZfRkVDRDFzalRreEZocWlQM0ZQN3pNb2EiLCJhbXIiOlsiQmFzaWNBdXRoZW50aW" +
                "NhdG9yIl0sImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTU5NTU4NDE3Mywia" +
                "WF0IjoxNTk1NTgwNTczLCJzaWQiOiI2NTdlMTUxMS0yZTkzLTQ2MDAtYjc3NC00ZmNjYTBmMjM2OGQifQ.brA_Dfvrol90ElI2e" +
                "uVFi7PIoRfU7OmFUig7cq1KiTBPtLxCG048PVSaQdUxMXfLuGjaA3qZLykZfViA1fos1ky-afFL5MmYrjdgxJdakxdTO1-5OYvY" +
                "TpEaUYfPj5twcm38o0C_za55PBxKw1egpKePLmrlKzw_DEXY4KQ815XwNGIZU8F3_LTbKVTQqsjWSfQAdL7_9cB3se37-TkByhm" +
                "l7RBSywUd86eBrTptKN6MaF4jVfALCof1DkWuZMoE07Z3q7jpnD1FFye5AjOHDN1v6hppOPypTjcl7CPV0DLiCE8m79SewEFYYS" +
                "wXBxsKABT58kJQwwPjjYaACSZb2Q";

        return new Object[][]{
                {encryptedIdToken, true},
                {idToken, false},
                {invalidIdToken, false},
                {"", false},
                {null, false}
        };
    }
}
