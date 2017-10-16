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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.config.OIDCSessionManagementConfiguration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuthServerConfiguration.class, OIDCSessionManagementConfiguration.class,
        IdentityCoreServiceComponent.class, IdentityUtil.class, OAuthServerConfiguration.class})
/***
 * Unit test coverage for OIDCSessionManagementUtil class
 */
public class OIDCSessionManagementUtilTest {

    @Mock
    OIDCSessionManagementConfiguration oidcSessionManagementConfiguration;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    private static final String CLIENT_ID = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static final String CALLBACK_URL = "http://localhost:8080/playground2/oauth2client";
    private static final String OPBROWSER_STATE = "090907ce-eab0-40d2-a46d-acd4bb33f0d0";
    private static final String SESSION_STATE = "18b2343e6edaec1c8b1208169ffa141d158156518135350be60dfbf6f41d340f" +
            ".W2Gf-RAzLUFy2xq_8tuM6A";
    String responseType[] = new String[]{"id_token", "token", "code" };

    @Test
    public void testGetSessionStateParam() {

        String state = OIDCSessionManagementUtil.getSessionStateParam(CLIENT_ID, CALLBACK_URL, OPBROWSER_STATE);
        Assert.assertNotNull(state, "This is empty");
    }

    /***
     * This provides data to testAddSessionStateToURL(String url, String sessionState, String responseType, String
     * actual)
     * @return
     */
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

        OAuthServerConfiguration mock = mock(OAuthServerConfiguration.class);
        when(mock.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mock);

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

    @Test (dataProvider = "provideDataForTestAddSessionStateToURL1")
    public void testAddSessionStateToURL1(String url, Object obpscookie) {

        OAuthServerConfiguration mock = mock(OAuthServerConfiguration.class);
        when(mock.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mock);

        String state = OIDCSessionManagementUtil.addSessionStateToURL(url, CLIENT_ID, CALLBACK_URL, (Cookie) obpscookie,
                responseType[1]);
        Assert.assertNotNull(state, "This is empty");
    }

    /***
     * This provides data to testGetOPBrowserStateCookie(Object cookie, Object expectedResult)
     * @return
     */
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

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn((Cookie[])cookie);
        Assert.assertEquals(OIDCSessionManagementUtil.getOPBrowserStateCookie(request), expectedResult);
    }

    @Test
    public void testAddOPBrowserStateCookie()  {

        HttpServletResponse response=mock(HttpServletResponse.class);
        Cookie cookie=OIDCSessionManagementUtil.addOPBrowserStateCookie(response);
        Assert.assertNotNull(cookie, "Opbs cookie is null");
    }

    /***
     * Provide data to testRemoveOPBrowserStateCookie(Object[] cookie, Object expected)
     * @return
     */
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

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn((Cookie[]) cookie);
        HttpServletResponse response = mock(HttpServletResponse.class);

        Cookie returnedCookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
        Assert.assertEquals(returnedCookie, expected, "Returned cookie is not equal as expected one");
    }

    @Test
    public void testGetOrigin() {

        String returnedUrl = OIDCSessionManagementUtil.getOrigin(CALLBACK_URL);
        Assert.assertEquals(returnedUrl, "http://localhost:8080", "Returned Url is different from expected url");
    }

    /***
     * Provides data to testGetOIDCLogoutConsentURL(String consentUrl, String expectedUrl)
     * @return
     */
    @DataProvider(name = "provideDataForTestGetOIDCLogoutConsentURL")
    public Object[][] provideDataForTestGetOIDCLogoutConsentURL() {

        String[] consentUrl = {"https://localhost:9443/authenticationendpoint/logout_consent.do",
                "https://localhost:9443/authenticationendpoint/oauth2_logout_consent.do" };
        return new Object[][]{
                {consentUrl[0], consentUrl[0]}, {"", consentUrl[1]}
        };
    }

    @Test(dataProvider = "provideDataForTestGetOIDCLogoutConsentURL")
    public void testGetOIDCLogoutConsentURL(String consentUrl, String expectedUrl) {

        mockStatic(OIDCSessionManagementConfiguration.class);
        when(OIDCSessionManagementConfiguration.getInstance()).thenReturn(oidcSessionManagementConfiguration);
        when(oidcSessionManagementConfiguration.getOIDCLogoutConsentPageUrl()).thenReturn(consentUrl);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL("/authenticationendpoint/oauth2_logout_consent.do", false,
                false))
                .thenReturn("https://localhost:9443/authenticationendpoint/oauth2_logout_consent.do");

        String returnedUrl = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
        Assert.assertEquals(returnedUrl, expectedUrl,"Consent Url is not same as the Expected Consent Url");
    }

    /***
     * Provides data to testGetOIDCLogoutURL(String logoutPageUrl, String expectedUrl)
     * @return
     */
    @DataProvider(name = "provideDataForTestGetOIDCLogoutURL")
    public Object[][] provideDataForTestGetOIDCLogoutURL() {

        String[] logoutPageUrl = {"https://localhost:9443/authenticationendpoint/logout.do",
                "https://localhost:9443/authenticationendpoint/oauth2_logout.do" };
        return new Object[][]{
                {logoutPageUrl[0], logoutPageUrl[0]},
                {"", logoutPageUrl[1]}
        };
    }

    @Test (dataProvider = "provideDataForTestGetOIDCLogoutURL")
    public void testGetOIDCLogoutURL(String logoutPageUrl, String expectedUrl) {
        mockStatic(OIDCSessionManagementConfiguration.class);
        when(OIDCSessionManagementConfiguration.getInstance()).thenReturn(oidcSessionManagementConfiguration);
        when(oidcSessionManagementConfiguration.getOIDCLogoutPageUrl()).thenReturn(logoutPageUrl);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL("/authenticationendpoint/oauth2_logout.do", false,
                false))
                .thenReturn("https://localhost:9443/authenticationendpoint/oauth2_logout.do");

        String returnedUrl = OIDCSessionManagementUtil.getOIDCLogoutURL();
        Assert.assertEquals(returnedUrl, expectedUrl, "Expected logout page url and actual logout url are " +
                "different");
    }

    /***
     * This provides data for testGetErrorPageURL(String errorPageUrl, String expectedUrl)
     * @return
     */
    @DataProvider(name = "provideDataForTestGetErrorPageURL")
    public Object[][] provideDataForTestGetErrorPageURL() {

        String[] errorPageUrl = {"https://localhost:9443/authenticationendpoint/error.do",
                "https://localhost:9443/authenticationendpoint/oauth2_error.do" };
        String[] expectedUrl = {"https://localhost:9443/authenticationendpoint/error" +
                ".do?oauthErrorCode=404&oauthErrorMsg=not+found",
                "https://localhost:9443/authenticationendpoint/oauth2_error" +
                        ".do?oauthErrorCode=404&oauthErrorMsg=not+found" };
        return new Object[][]{
                {errorPageUrl[0], expectedUrl[0]},
                {"", expectedUrl[1]}
        };
    }

    @Test(dataProvider = "provideDataForTestGetErrorPageURL")
    public void testGetErrorPageURL(String errorPageUrl, String expectedUrl) {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getOauth2ErrorPageUrl()).thenReturn(errorPageUrl);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL("/authenticationendpoint/oauth2_error.do", false,
                false))
                .thenReturn("https://localhost:9443/authenticationendpoint/oauth2_error.do" );
        String returnedErrorPageUrl = OIDCSessionManagementUtil.getErrorPageURL("404", "not found" );
        Assert.assertEquals(returnedErrorPageUrl,expectedUrl, "Expected error page url and actual url are " +
                "different" );
    }

    @Test
    public void testGetOpenIDConnectSkipeUserConsent() {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getOpenIDConnectSkipeUserConsentConfig()).thenReturn(true);
        boolean returned = OIDCSessionManagementUtil.getOpenIDConnectSkipeUserConsent();
        Assert.assertEquals(returned, true, "Expected value and actual value are different");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

}
