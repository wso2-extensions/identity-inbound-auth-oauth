/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oidc.session.frontchannellogout;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for DynamicLogoutPageBuilderUtil.
 */
public class DynamicLogoutPageBuilderUtilTest {

    private static final String CLIENT_ID_1 = "client123";
    private static final String FRONTCHANNEL_LOGOUT_URL_1 = "https://app1.example.com/logout";
    private static final String REDIRECT_URL = "https://idp.example.com/commonauth";
    private static final String SID = "session123";
    private static final String ISSUER = "https://idp.example.com/oauth2/token";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final Log LOG = LogFactory.getLog(DynamicLogoutPageBuilderUtilTest.class);

    @DataProvider(name = "frontchannelLogoutDataProvider")
    public Object[][] provideFrontchannelLogoutData() {
        return new Object[][]{
                // hasSessionState, hasParticipants, expectIframes
                // Valid URLs will generate iframes (URL is not blank and not "null")
                {true, true, true},   // Valid URL generates iframe
                {true, false, false}, // No participants, no iframe
                {false, false, false} // No session state, no iframe
        };
    }

    @Test(dataProvider = "frontchannelLogoutDataProvider")
    public void testBuildPage(boolean hasSessionState, boolean hasParticipants, boolean expectIframes) {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        OIDCSessionState mockSessionState = mock(OIDCSessionState.class);
        OAuthAppDO mockOAuthAppDO1 = mock(OAuthAppDO.class);

        try (MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtilMock =
                     mockStatic(OIDCSessionManagementUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMock = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockStatic(FrameworkUtils.class)) {

            // Setup session state
            if (hasSessionState) {
                oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionState(mockRequest))
                        .thenReturn(mockSessionState);
                when(mockSessionState.getSidClaim()).thenReturn(SID);

                if (hasParticipants) {
                    Set<String> participants = new HashSet<>();
                    participants.add(CLIENT_ID_1);

                    oidcSessionManagementUtilMock.when(() ->
                                    OIDCSessionManagementUtil.getSessionParticipants(mockSessionState))
                            .thenReturn(participants);
                    oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.resolveTenantDomain(mockRequest))
                            .thenReturn(TENANT_DOMAIN);
                    oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getIdTokenIssuer(TENANT_DOMAIN))
                            .thenReturn(ISSUER);

                    identityTenantUtilMock.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(TENANT_DOMAIN);

                    // Return a valid URL (not "null")
                    when(mockOAuthAppDO1.getFrontchannelLogoutUrl()).thenReturn(FRONTCHANNEL_LOGOUT_URL_1);
                    oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_1, TENANT_DOMAIN))
                            .thenReturn(mockOAuthAppDO1);

                    String url1WithParams = FRONTCHANNEL_LOGOUT_URL_1 + "?sid=" + SID + "&iss=" + ISSUER;
                    frameworkUtilsMock.when(() -> FrameworkUtils.buildURLWithQueryParams(anyString(), any(Map.class)))
                            .thenReturn(url1WithParams);
                } else {
                    oidcSessionManagementUtilMock.when(() ->
                                    OIDCSessionManagementUtil.getSessionParticipants(mockSessionState))
                            .thenReturn(new HashSet<>());
                }
            } else {
                oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionState(mockRequest))
                        .thenReturn(null);
            }

            // Execute
            String htmlPage = DynamicLogoutPageBuilderUtil.buildPage(mockRequest, mockSessionState);

            // Verify
            assertNotNull(htmlPage);
            assertTrue(htmlPage.contains("<html>"));
            assertTrue(htmlPage.contains("</html>"));
            assertTrue(htmlPage.contains("function redirect()"));

            if (expectIframes) {
                // Valid URL generates an iframe
                assertTrue(htmlPage.contains("if(count === 1){"), "Expected count === 1 in HTML page");
                assertTrue(htmlPage.contains("<iframe"), "Expected iframe tag in HTML page");
                assertTrue(htmlPage.contains("onload=\"onIFrameLoad()\""), "Expected onload attribute");
            } else {
                // No participants or no session - immediate redirect
                assertTrue(htmlPage.contains("if(count === 0){"), "Expected count === 0 check in HTML page");
                assertTrue(htmlPage.contains("redirect();"), "Expected redirect() call in HTML page");
            }
        }
    }

    @Test
    public void testBuildPageWithNullFrontchannelUrl() {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        OIDCSessionState mockSessionState = mock(OIDCSessionState.class);
        OAuthAppDO mockOAuthAppDO1 = mock(OAuthAppDO.class);

        try (MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtilMock =
                     mockStatic(OIDCSessionManagementUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMock = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockStatic(FrameworkUtils.class)) {

            Set<String> participants = new HashSet<>();
            participants.add(CLIENT_ID_1);

            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionState(mockRequest))
                    .thenReturn(mockSessionState);
            when(mockSessionState.getSidClaim()).thenReturn(SID);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionParticipants(mockSessionState))
                    .thenReturn(participants);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.resolveTenantDomain(mockRequest))
                    .thenReturn(TENANT_DOMAIN);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getIdTokenIssuer(TENANT_DOMAIN))
                    .thenReturn(ISSUER);

            identityTenantUtilMock.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(TENANT_DOMAIN);

            // Return null for frontchannel logout URL
            when(mockOAuthAppDO1.getFrontchannelLogoutUrl()).thenReturn(null);
            oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_1, TENANT_DOMAIN))
                    .thenReturn(mockOAuthAppDO1);

            // Execute
            String htmlPage = DynamicLogoutPageBuilderUtil.buildPage(mockRequest, mockSessionState);

            // Verify - should generate page with no iframes since logout URL is null
            assertNotNull(htmlPage);
            assertTrue(htmlPage.contains("if(count === 0){"));
            assertTrue(htmlPage.contains("redirect();"));
        }
    }

    @Test
    public void testBuildPageWithStringNullFrontchannelUrl() {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        OIDCSessionState mockSessionState = mock(OIDCSessionState.class);
        OAuthAppDO mockOAuthAppDO1 = mock(OAuthAppDO.class);

        try (MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtilMock =
                     mockStatic(OIDCSessionManagementUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMock = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockStatic(FrameworkUtils.class)) {

            Set<String> participants = new HashSet<>();
            participants.add(CLIENT_ID_1);

            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionState(mockRequest))
                    .thenReturn(mockSessionState);
            when(mockSessionState.getSidClaim()).thenReturn(SID);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionParticipants(mockSessionState))
                    .thenReturn(participants);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.resolveTenantDomain(mockRequest))
                    .thenReturn(TENANT_DOMAIN);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getIdTokenIssuer(TENANT_DOMAIN))
                    .thenReturn(ISSUER);

            identityTenantUtilMock.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(TENANT_DOMAIN);

            // Return "null" string for frontchannel logout URL
            String frontchannelLogoutUrl = "null";
            when(mockOAuthAppDO1.getFrontchannelLogoutUrl()).thenReturn(frontchannelLogoutUrl);
            oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_1, TENANT_DOMAIN))
                    .thenReturn(mockOAuthAppDO1);

            // Execute
            String htmlPage = DynamicLogoutPageBuilderUtil.buildPage(mockRequest, mockSessionState);

            // Verify - should generate page with no iframes since logout URL equals "null"
            // The implementation checks !StringUtils.equalsIgnoreCase("null", frontchannelLogoutURL)
            // so "null" URLs are filtered out
            assertNotNull(htmlPage);
            LOG.info(htmlPage);
            assertTrue(htmlPage.contains("if(count === 0){"));
            assertTrue(htmlPage.contains("redirect();"));
        }
    }

    @Test
    public void testSetRedirectURL() {
        // Create a basic HTML page with redirect URL placeholder
        String htmlPage = "<html><body><script>window.location = \"${redirectURL}\";</script></body></html>";

        // Execute
        String result = DynamicLogoutPageBuilderUtil.setRedirectURL(htmlPage, REDIRECT_URL);

        // Verify
        assertNotNull(result);
        assertTrue(result.contains(REDIRECT_URL));
        assertFalse(result.contains("${redirectURL}"));
    }

    @Test
    public void testSetRedirectURLWithNullHtmlPage() {
        // Execute with null HTML page
        String result = DynamicLogoutPageBuilderUtil.setRedirectURL(null, REDIRECT_URL);

        // Verify - should return null
        assertNull(result);
    }

    @Test
    public void testBuildPageIntegrationWithSetRedirectURL() {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        OIDCSessionState mockSessionState = mock(OIDCSessionState.class);
        OAuthAppDO mockOAuthAppDO1 = mock(OAuthAppDO.class);

        try (MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtilMock =
                     mockStatic(OIDCSessionManagementUtil.class);
             MockedStatic<OAuth2Util> oAuth2UtilMock = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockStatic(FrameworkUtils.class)) {

            Set<String> participants = new HashSet<>();
            participants.add(CLIENT_ID_1);

            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionState(mockRequest))
                    .thenReturn(mockSessionState);
            when(mockSessionState.getSidClaim()).thenReturn(SID);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getSessionParticipants(mockSessionState))
                    .thenReturn(participants);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.resolveTenantDomain(mockRequest))
                    .thenReturn(TENANT_DOMAIN);
            oidcSessionManagementUtilMock.when(() -> OIDCSessionManagementUtil.getIdTokenIssuer(TENANT_DOMAIN))
                    .thenReturn(ISSUER);

            identityTenantUtilMock.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(TENANT_DOMAIN);

            when(mockOAuthAppDO1.getFrontchannelLogoutUrl()).thenReturn(FRONTCHANNEL_LOGOUT_URL_1);
            oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_1, TENANT_DOMAIN))
                    .thenReturn(mockOAuthAppDO1);

            String url1WithParams = FRONTCHANNEL_LOGOUT_URL_1 + "?sid=" + SID + "&iss=" + ISSUER;
            frameworkUtilsMock.when(() -> FrameworkUtils.buildURLWithQueryParams(anyString(), any(Map.class)))
                    .thenReturn(url1WithParams);

            // Execute
            String htmlPage = DynamicLogoutPageBuilderUtil.buildPage(mockRequest, mockSessionState);
            String finalPage = DynamicLogoutPageBuilderUtil.setRedirectURL(htmlPage, REDIRECT_URL);

            // Verify
            assertNotNull(finalPage);
            assertTrue(finalPage.contains(FRONTCHANNEL_LOGOUT_URL_1));
            assertTrue(finalPage.contains(REDIRECT_URL));
            assertTrue(finalPage.contains("window.location = \"" + REDIRECT_URL + "\""));
            assertFalse(finalPage.contains("${redirectURL}"));
        }
    }
}

