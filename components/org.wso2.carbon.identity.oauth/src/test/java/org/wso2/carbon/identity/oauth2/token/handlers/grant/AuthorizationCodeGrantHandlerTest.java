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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.lang.StringUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * This class defines unit test for AuthorizationCodeGrantHandler class
 */
@WithCarbonHome
public class AuthorizationCodeGrantHandlerTest {

    public static final String CLIENT_ID_VALUE = "clientIdValue";
    public static final String INVALID_CLIENT = "invalidClient";
    OAuthServerConfiguration mockOAuthServerConfiguration;
    AuthorizationCodeGrantHandler authorizationCodeGrantHandler;

    @BeforeTest()
    public void setUp() {
    }

    @DataProvider(name = "BuildTokenRequestMessageContext")
    public Object[][] buildTokenRequestMessageContext() throws Exception {

        OAuthTokenReqMessageContext messageContext1 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext1.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");

        OAuthTokenReqMessageContext messageContext2 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        messageContext2.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        messageContext2.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl");

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        setPrivateField(authzCodeDO1, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO1, "callbackUrl", "callBackUrl");

        AuthzCodeDO authzCodeDO2 = new AuthzCodeDO();

        return new Object[][] {
                {messageContext1, authzCodeDO2, false, true, System.currentTimeMillis() + 250000L, true},
                {messageContext2, authzCodeDO1, true, false, System.currentTimeMillis() + 250000L, true},
        };
    }

    @Test(dataProvider = "BuildTokenRequestMessageContext")
    public void testValidateGrant(Object tokenRequestMessageContext, Object authzCode, boolean cacheEnabled,
                                  boolean debugEnabled, long timestamp, boolean expectedResult)
            throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class)) {
            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", cacheEnabled);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            if (cacheEnabled) {
                setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            }
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

            OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
//            whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
            when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(oAuthAppDO);

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            doNothing().when(mockAppInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

            assertEquals(authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx), expectedResult);
        }
    }

    @DataProvider(name = "buildErrorTokenRequestMessageContext")
    public Object[][] buildErrorTokenRequestMessageContext() throws Exception {

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext1 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext1.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        oAuthTokenReqMessageContext1.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl2");

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext2 = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext2.getOauth2AccessTokenReqDTO().setAuthorizationCode("123456");
        oAuthTokenReqMessageContext2.getOauth2AccessTokenReqDTO().setCallbackURI("callBackUrl");

        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        authzCodeDO1.setState(OAuthConstants.AuthorizationCodeState.INACTIVE);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("user");
        setPrivateField(authzCodeDO1, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO1, "callbackUrl", "callBackUrl");
        setPrivateField(authzCodeDO1, "state", "INACTIVE");

        AuthzCodeDO authzCodeDO2 = new AuthzCodeDO();
        setPrivateField(authzCodeDO2, "authorizedUser", authenticatedUser);
        setPrivateField(authzCodeDO2, "callbackUrl", "callBackUrl");
        setPrivateField(authzCodeDO2, "validityPeriod", 3000000L);

        return new Object[][]{
                {oAuthTokenReqMessageContext1, null, CLIENT_ID_VALUE, true, 1000L, "Invalid authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO1, CLIENT_ID_VALUE, true, 1000L,
                        "Inactive authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, 1000L,
                        "Expired authorization code"},
                {oAuthTokenReqMessageContext1, authzCodeDO2, CLIENT_ID_VALUE, true, System.currentTimeMillis(),
                        "Callback url mismatch"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, CLIENT_ID_VALUE, false, System.currentTimeMillis(),
                        "PKCE validation failed"},
                {oAuthTokenReqMessageContext2, authzCodeDO2, INVALID_CLIENT, true, System.currentTimeMillis(),
                        "Error while retrieving app information"},
        };
    }

    @Test(dataProvider = "buildErrorTokenRequestMessageContext")
    public void testValidateGrantException(Object tokenRequestMessageContext, Object authzCode, String clientId,
                                           boolean pkceValid, long timestamp, String expectedError) throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class);) {
            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", true);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            TokenPersistenceProcessor tokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);

            OAuthAppDAO oAuthAppDAO = mock(OAuthAppDAO.class);
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
//            whenNew(OAuthAppDAO.class).withNoArguments().thenReturn(oAuthAppDAO);
            when(oAuthAppDAO.getAppInformation(CLIENT_ID_VALUE)).thenReturn(oAuthAppDO);
            when(oAuthAppDAO.getAppInformation(INVALID_CLIENT)).thenThrow(new InvalidOAuthClientException("Error"));

            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            doNothing().when(mockAppInfoCache).addToCache(anyString(), any(OAuthAppDO.class));

//            spy(OAuth2Util.class);
//            doReturn(pkceValid).when(OAuth2Util.class, "validatePKCE", anyString(), anyString(), anyString(),
//                    any(OAuthAppDO.class));
            try {
                authorizationCodeGrantHandler.validateGrant(tokReqMsgCtx);
                fail("Expected exception not thrown");
            } catch (IdentityOAuth2Exception e) {
                assertTrue(e.getMessage().contains(expectedError),
                        "Expected error message with '" + expectedError + "'");
            }
        }
    }

    @DataProvider(name = "BuildTokenMsgCtxForIssue")
    public Object[][] buildTokenMsgCtxForIssue() {

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        oAuthTokenReqMessageContext.setAuthorizedUser(new AuthenticatedUser());
        oAuthTokenReqMessageContext.getAuthorizedUser().setUserName("user");
        oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().setGrantType("grant");
        return new Object[][] {
            {oAuthTokenReqMessageContext, false, false},
            {oAuthTokenReqMessageContext, false, true},
            {oAuthTokenReqMessageContext, true, false},
            {oAuthTokenReqMessageContext, true, true}
        };
    }

    @Test(dataProvider = "BuildTokenMsgCtxForIssue")
    public void testIssue(Object tokenRequestMessageContext, boolean enableCache, boolean debugEnabled)
            throws Exception {

        try (MockedStatic<OAuthCache> oAuthCache = mockStatic(OAuthCache.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            setPrivateField(authorizationCodeGrantHandler, "cacheEnabled", enableCache);
            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            oAuthCache.when(OAuthCache::getInstance).thenReturn(mockOAuthCache);

            if (enableCache) {
                setPrivateField(authorizationCodeGrantHandler, "oauthCache", mockOAuthCache);
            }
            OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;

            OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuer.class);
            setPrivateField(authorizationCodeGrantHandler, "oauthIssuerImpl", oauthTokenIssuer);

            OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
            oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
            when(oauthTokenIssuer.accessToken(tokReqMsgCtx)).thenReturn(StringUtils.EMPTY);

            assertNotNull(authorizationCodeGrantHandler.issue(tokReqMsgCtx));
        }

    }

    @Test
    public void testAuthorizeAccessDelegation() throws IdentityOAuth2Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                     OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            assertTrue(authorizationCodeGrantHandler.authorizeAccessDelegation(new OAuthTokenReqMessageContext
                    (new OAuth2AccessTokenReqDTO())));
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testStoreAccessToken() throws IdentityException {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

            authorizationCodeGrantHandler.storeAccessToken(new OAuth2AccessTokenReqDTO(),
                    TestConstants.USERSTORE_DOMAIN,
                    new AccessTokenDO(), TestConstants.NEW_ACCESS_TOKEN, new AccessTokenDO());
        }
    }

    @Test
    public void testIssueRefreshToken() throws IdentityOAuth2Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class)) {
            mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
            when(mockOAuthServerConfiguration.getValueForIsRefreshTokenAllowed(
                    OAuthConstants.GrantTypes.AUTHORIZATION_CODE)).
                    thenReturn(true, false);

            assertTrue(authorizationCodeGrantHandler.issueRefreshToken());

            assertFalse(authorizationCodeGrantHandler.issueRefreshToken());
        }
    }

    /**
     * Verifies that setSessionDataKeyConsentProperty() sets SESSION_DATA_KEY_CONSENT on the message context
     * when the cache entry exists and sessionDataKeyConsent is populated.
     */
    @Test
    public void testSetSessionDataKeyConsentProperty_withValidConsent() throws Exception {

        String authzCode = "test-authz-code";
        String sessionDataKeyConsent = "test-session-data-key-consent";
        AuthorizationCodeGrantHandler handler = new AuthorizationCodeGrantHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic =
                     mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);

            AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry();
            cacheEntry.setSessionDataKeyConsent(sessionDataKeyConsent);
            when(mockCache.getValueFromCacheByCode(
                    any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Method method = AuthorizationCodeGrantHandler.class.getDeclaredMethod(
                    "setSessionDataKeyConsentProperty",
                    OAuthTokenReqMessageContext.class, String.class);
            method.setAccessible(true);
            method.invoke(handler, tokReqMsgCtx, authzCode);

            assertEquals(tokReqMsgCtx.getProperty(OAuthConstants.SESSION_DATA_KEY_CONSENT),
                    sessionDataKeyConsent);
        }
    }

    /**
     * Verifies that setSessionDataKeyConsentProperty() does not set any property
     * when the cache entry is null (e.g. cache and session store both miss).
     */
    @Test
    public void testSetSessionDataKeyConsentProperty_withNullCacheEntry() throws Exception {

        String authzCode = "test-authz-code-null";
        AuthorizationCodeGrantHandler handler = new AuthorizationCodeGrantHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic =
                     mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByCode(
                    any(AuthorizationGrantCacheKey.class))).thenReturn(null);

            Method method = AuthorizationCodeGrantHandler.class.getDeclaredMethod(
                    "setSessionDataKeyConsentProperty",
                    OAuthTokenReqMessageContext.class, String.class);
            method.setAccessible(true);
            method.invoke(handler, tokReqMsgCtx, authzCode);

            assertNull(tokReqMsgCtx.getProperty(OAuthConstants.SESSION_DATA_KEY_CONSENT));
        }
    }

    /**
     * Verifies that setSessionDataKeyConsentProperty() does not set any property
     * when the cache entry exists but sessionDataKeyConsent is empty.
     */
    @Test
    public void testSetSessionDataKeyConsentProperty_withEmptyConsent() throws Exception {

        String authzCode = "test-authz-code-empty";
        AuthorizationCodeGrantHandler handler = new AuthorizationCodeGrantHandler();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(
                new OAuth2AccessTokenReqDTO());

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic =
                     mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);

            AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry();
            cacheEntry.setSessionDataKeyConsent("");
            when(mockCache.getValueFromCacheByCode(
                    any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            Method method = AuthorizationCodeGrantHandler.class.getDeclaredMethod(
                    "setSessionDataKeyConsentProperty",
                    OAuthTokenReqMessageContext.class, String.class);
            method.setAccessible(true);
            method.invoke(handler, tokReqMsgCtx, authzCode);

            assertNull(tokReqMsgCtx.getProperty(OAuthConstants.SESSION_DATA_KEY_CONSENT));
        }
    }

    /**
     * Verifies that resolveSharedUserDetails marks the user as shared and resolves both resident and accessing
     * organizations via OrganizationManager when the cache entry signals IS_SHARED_USER and there is no
     * application resident organization in the carbon context (i.e. tenant-bound login flow).
     */
    @Test
    public void testResolveSharedUserDetailsMarksUserSharedAndResolvesOrgs() throws Exception {

        String authCode = "shared-user-auth-code";
        String userTenantDomain = "user.tenant.com";
        String accessingTenantDomain = "accessing.tenant.com";
        String residentOrgId = "user-resident-org-id";
        String accessingOrgId = "user-accessing-org-id";

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("sharedUser");
        user.setTenantDomain(userTenantDomain);

        Map<String, String> extensionParams = new HashMap<>();
        extensionParams.put(OAuthConstants.IS_SHARED_USER, "true");
        AccessTokenExtendedAttributes extendedAttributes = new AccessTokenExtendedAttributes(extensionParams);

        AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry();
        cacheEntry.setAccessTokenExtensionDO(extendedAttributes);

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveOrganizationId(userTenantDomain)).thenReturn(residentOrgId);
        when(organizationManager.resolveOrganizationId(accessingTenantDomain)).thenReturn(accessingOrgId);

        OrganizationManager originalOrgManager = OAuthComponentServiceHolder.getInstance().getOrganizationManager();
        OAuthComponentServiceHolder.getInstance().setOrganizationManager(organizationManager);

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic = mockStatic(AuthorizationGrantCache.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);
            identityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(accessingTenantDomain);

            // Ensure no application resident organization is set (regular tenant flow).
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setApplicationResidentOrganizationId(null);

            invokeResolveSharedUserDetails(user, authCode);

            assertTrue(user.isSharedUser(), "User should be flagged as shared.");
            assertEquals(user.getUserResidentOrganization(), residentOrgId);
            assertEquals(user.getAccessingOrganization(), accessingOrgId);
        } finally {
            OAuthComponentServiceHolder.getInstance().setOrganizationManager(originalOrgManager);
        }
    }

    /**
     * Verifies that resolveSharedUserDetails sets the shared user flag but does NOT resolve organization details
     * when the carbon context already has applicationResidentOrganizationId set (i.e. sub-org application login
     * where these values are already populated upstream).
     */
    @Test
    public void testResolveSharedUserDetailsSkipsOrgResolutionWhenAppResidentOrgIsSet() throws Exception {

        String authCode = "shared-user-auth-code-suborg";
        String preSetAccessingOrg = "pre-set-accessing-org";
        String preSetResidentOrg = "pre-set-resident-org";

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("sharedUser");
        user.setTenantDomain("user.tenant.com");
        user.setAccessingOrganization(preSetAccessingOrg);
        user.setUserResidentOrganization(preSetResidentOrg);

        Map<String, String> extensionParams = new HashMap<>();
        extensionParams.put(OAuthConstants.IS_SHARED_USER, "true");
        AccessTokenExtendedAttributes extendedAttributes = new AccessTokenExtendedAttributes(extensionParams);

        AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry();
        cacheEntry.setAccessTokenExtensionDO(extendedAttributes);

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        OrganizationManager originalOrgManager = OAuthComponentServiceHolder.getInstance().getOrganizationManager();
        OAuthComponentServiceHolder.getInstance().setOrganizationManager(organizationManager);

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic = mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            // Simulate sub-organization application login by setting the resident org id on carbon context.
            PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .setApplicationResidentOrganizationId("sub-org-app-resident-id");
            try {
                invokeResolveSharedUserDetails(user, authCode);
            } finally {
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setApplicationResidentOrganizationId(null);
            }

            assertTrue(user.isSharedUser(), "User should be flagged as shared.");
            // OrganizationManager should NOT have been consulted; pre-set values must remain unchanged.
            verify(organizationManager, never()).resolveOrganizationId(anyString());
            assertEquals(user.getAccessingOrganization(), preSetAccessingOrg);
            assertEquals(user.getUserResidentOrganization(), preSetResidentOrg);
        } finally {
            OAuthComponentServiceHolder.getInstance().setOrganizationManager(originalOrgManager);
        }
    }

    /**
     * Verifies that resolveSharedUserDetails leaves the user untouched when the cache entry has no extension DO
     * or when IS_SHARED_USER is not set.
     */
    @Test
    public void testResolveSharedUserDetailsNoOpForNonSharedUser() throws Exception {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("regularUser");
        user.setTenantDomain("user.tenant.com");

        // Cache entry without an AccessTokenExtensionDO at all.
        AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry();

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic = mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            invokeResolveSharedUserDetails(user, "no-shared-flag-code");

            assertFalse(user.isSharedUser(), "User must remain non-shared when no IS_SHARED_USER flag is present.");
            assertNull(user.getAccessingOrganization());
            assertNull(user.getUserResidentOrganization());
        }
    }

    /**
     * Verifies that for organization SSO federated users, the accessing organization in the cache entry takes
     * precedence over the user-resident organization claim when populating the authenticated user.
     */
    @Test
    public void testResolveAccessingAndResidentOrgsUsesCachedAccessingOrganization() throws Exception {

        String authzCode = "org-sso-auth-code";
        String accessingOrgFromCache = "cached-accessing-org";
        String residentOrgFromClaim = "claimed-resident-org";

        AuthenticatedUser user = new AuthenticatedUser();
        user.setFederatedUser(true);
        user.setFederatedIdPName(FrameworkConstants.ORGANIZATION_LOGIN_IDP_NAME);

        AuthorizationGrantCacheEntry cacheEntry = new AuthorizationGrantCacheEntry(
                buildUserOrganizationAttributes(residentOrgFromClaim));
        cacheEntry.setAccessingOrganization(accessingOrgFromCache);

        try (MockedStatic<AuthorizationGrantCache> mockCacheStatic = mockStatic(AuthorizationGrantCache.class)) {

            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mockCacheStatic.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByCode(any(AuthorizationGrantCacheKey.class))).thenReturn(cacheEntry);

            invokeResolveAccessingAndResidentOrgs(user, authzCode);

            assertEquals(user.getAccessingOrganization(), accessingOrgFromCache,
                    "Accessing organization must come from the cache entry when set.");
            assertEquals(user.getUserResidentOrganization(), residentOrgFromClaim);
        }
    }

    private void invokeResolveSharedUserDetails(AuthenticatedUser user, String authCode) throws Exception {

        Method method = AuthorizationCodeGrantHandler.class.getDeclaredMethod(
                "resolveSharedUserDetails", AuthenticatedUser.class, String.class);
        method.setAccessible(true);
        method.invoke(new AuthorizationCodeGrantHandler(), user, authCode);
    }

    private void invokeResolveAccessingAndResidentOrgs(AuthenticatedUser user, String authzCode) throws Exception {

        Method method = AuthorizationCodeGrantHandler.class.getDeclaredMethod(
                "resolveAccessingAndResidentOrgsForOrganizationSSOUsers",
                AuthenticatedUser.class, String.class);
        method.setAccessible(true);
        method.invoke(new AuthorizationCodeGrantHandler(), user, authzCode);
    }

    private Map<ClaimMapping, String> buildUserOrganizationAttributes(String organizationId) {

        Map<ClaimMapping, String> attributes = new HashMap<>();
        ClaimMapping mapping = new ClaimMapping();
        Claim localClaim = new Claim();
        localClaim.setClaimUri(FrameworkConstants.USER_ORGANIZATION_CLAIM);
        Claim remoteClaim = new Claim();
        remoteClaim.setClaimUri(FrameworkConstants.USER_ORGANIZATION_CLAIM);
        mapping.setLocalClaim(localClaim);
        mapping.setRemoteClaim(remoteClaim);
        attributes.put(mapping, organizationId);
        return attributes;
    }

    private void setPrivateField(Object object, String fieldName, Object value) throws Exception {

        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }
}
