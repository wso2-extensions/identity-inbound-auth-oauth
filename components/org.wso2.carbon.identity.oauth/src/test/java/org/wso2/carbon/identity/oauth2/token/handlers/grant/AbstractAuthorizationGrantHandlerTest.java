/*
 * Copyright (c) 2017-2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthCallbackHandlerMetaData;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_REVOKED;

@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/identity.sql", "dbScripts/insert_application_and_token.sql",
                "dbScripts/insert_consumer_app.sql", "dbScripts/insert_local_idp.sql"})
@WithRealmService(injectToSingletons = {OAuthComponentServiceHolder.class})
public class AbstractAuthorizationGrantHandlerTest {

    private AbstractAuthorizationGrantHandler handler;
    @Mock
    private ActionExecutorService mockActionExecutionService;

    private RefreshGrantHandler refreshGrantHandler;
    private AuthenticatedUser authenticatedUser;
    private String clientId;
    private String appId = "TestApp1";
    private static final String OAUTH_APP_PROPERTY = "OAuthAppDO";

    private static final String CUSTOM_GRANT = "custom grant";
    private static final String DEFAULT_CALLBACK_HANDLER_CLASS_NAME =
            "org.wso2.carbon.identity.oauth.callback.DefaultCallbackHandler";
    private static final String PASSWORD_GRANT = "password";
    private OAuthAppDO oAuthAppDO;
    private MockedStatic<AuthzUtil> mockedAuthzUtil;

    @BeforeMethod
    public void setUp() throws IdentityOAuth2Exception, IdentityOAuthAdminException, ActionExecutionException {
        authenticatedUser = new AuthenticatedUser() {

        };
        OAuthComponentServiceHolder.getInstance().setRealmService(IdentityTenantUtil.getRealmService());

        OAuthComponentServiceHolder.getInstance().setActionExecutorService(mockActionExecutionService);
        MockitoAnnotations.initMocks(this);
        when(mockActionExecutionService.execute(any(ActionType.class), anyMap(), any())).thenReturn(
                new SuccessStatus.Builder().build());

        authenticatedUser.setUserName("randomUser");
        authenticatedUser.setTenantDomain("Homeless");
        authenticatedUser.setUserStoreDomain("Street");
        authenticatedUser.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        clientId = UUID.randomUUID().toString();
        appId = clientId;

        handler = new MockAuthzGrantHandler();
        handler.init();

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setApplicationName(appId);
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setCallbackUrl("http://i.have.nowhere.to.go");
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);

        oAuthAppDAO.addOAuthApplication(oAuthAppDO);

    }

    @BeforeClass
    public void setUpMocks() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        Mockito.clearAllCaches();
        mockedAuthzUtil = mockStatic(AuthzUtil.class);
        mockedAuthzUtil.when(AuthzUtil::isLegacyAuthzRuntime).thenReturn(false);
    }

    @AfterClass
    public void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
        mockedAuthzUtil.close();
    }

    @Test(dataProvider = "IssueWithRenewDataProvider", expectedExceptions = IdentityOAuth2Exception.class)
    public void testIssueWithRenewWithoutRevokingExistingEnabled
            (boolean cacheEnabled, boolean cacheEntryAvailable, long cachedTokenValidity,
             long cachedRefreshTokenValidity, long dbTokenValidity, long dbRefreshTokenValidity,
             boolean dbEntryAvailable, String dbTokenState, boolean tokenLoggable, boolean isIDPIdColumnEnabled,
             boolean setBindingReference) throws Exception {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);

        Map<String, AuthorizationGrantHandler> supportedGrantTypes = new HashMap<>();
        supportedGrantTypes.put("refresh_token", refreshGrantHandler);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId(clientId);
        oAuth2AccessTokenReqDTO.setGrantType(PASSWORD_GRANT);  // Ensure the grant type is valid for renewal

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
        tokReqMsgCtx.setScope(new String[]{"scope1", "scope2"});

        tokReqMsgCtx.addProperty("OAuthAppDO", oAuthAppDO);

        TokenBinding tokenBinding = new TokenBinding();
        if (setBindingReference) {
            tokenBinding.setBindingReference("bindingReference");
        }
        tokReqMsgCtx.setTokenBinding(tokenBinding);

        // Mocking static methods using try-with-resources
        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> oauth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {

            identityUtil.when(() -> IdentityUtil.getProperty(anyString()))
                    .thenReturn(Boolean.TRUE.toString());

            OAuthComponentServiceHolder.getInstance().setActionExecutorService(mockActionExecutionService);
            OAuthTokenPersistenceFactory persistenceFactory = mock(OAuthTokenPersistenceFactory.class);
            when(persistenceFactory.getAccessTokenDAO()).thenReturn(new AccessTokenDAOImpl());

            OauthTokenIssuer oauthTokenIssuer = mock(JWTTokenIssuer.class);
            when(oauthTokenIssuer.getAccessTokenType()).thenReturn("jwt");
            oauth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(clientId)).thenReturn(oauthTokenIssuer);
            oauth2Util.when(() -> OAuth2Util.getAppInformationByClientId(eq(clientId), anyString())).
                    thenReturn(oAuthAppDO);

            identityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(-1234);
            // Set allowed grant types (ensure PASSWORD_GRANT is allowed for renewal)
            OAuth2ServiceComponentHolder.setJwtRenewWithoutRevokeAllowedGrantTypes(
                    Collections.singletonList("password")); // This allows PASSWORD_GRANT

            OAuth2AccessTokenRespDTO tokenRespDTO = handler.issue(tokReqMsgCtx);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @DataProvider(name = "IssueDataProvider")
    public Object[][] issueDataProvider() {
        return new Object[][] {
                { true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, true },
                { true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, false },
                { true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, true },
                { true, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, false },
                { false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false, true },
                { false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false, false },
                { false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false, true },
                { false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false, false },
                { true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, false, true },
                { true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, false, false },
                { true, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, false, true },
                { true, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, false, false },

                {true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true, true},
                {true, true, 0L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true, false},
                {true, true, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true, true},
                {true, false, 0L, 0L, 0L, 0L, false, TOKEN_STATE_ACTIVE, true, false},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true, true},
                {false, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true, false},
                {false, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true, true},
                {false, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true, false},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_ACTIVE, true, true},
                {true, false, 0L, 0L, 3600L, 0L, true, TOKEN_STATE_REVOKED, true, false},
                {true, false, 0L, 0L, 0L, 0L, true, TOKEN_STATE_ACTIVE, true, true},
                {true, false, 0L, 0L, 0L, 3600L, true, TOKEN_STATE_ACTIVE, true, false},
                {true, true, 0L, 0L, -1L, 3600L, true, TOKEN_STATE_ACTIVE, true, true},
                {false, true, 0L, 0L, -1L, 3600L, true, TOKEN_STATE_ACTIVE, true, false}};
    }

    @DataProvider(name = "IssueWithRenewDataProvider")
    public Object[][] issueWithRenewDataProvider() {
        return new Object[][]{
                {true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, true, true},
                {true, true, 3600L, 3600L, 0L, 0L, false, TOKEN_STATE_ACTIVE, false, true, false}
        };
    }

    @Test(dataProvider = "IssueDataProvider")
    public void testIssue(boolean cacheEnabled, boolean cacheEntryAvailable, long cachedTokenValidity,
                          long cachedRefreshTokenValidity, long dbTokenValidity, long dbRefreshTokenValidity,
                          boolean dbEntryAvailable, String dbTokenState, boolean tokenLoggable,
                          boolean isIDPIdColumnEnabled)
            throws Exception {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        OAuthComponentServiceHolder.getInstance().setActionExecutorService(mockActionExecutionService);

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);

        Map<String, AuthorizationGrantHandler> supportedGrantTypes = new HashMap<>();
        supportedGrantTypes.put("refresh_token", refreshGrantHandler);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId(clientId);
        oAuth2AccessTokenReqDTO.setGrantType(PASSWORD_GRANT);

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
        tokReqMsgCtx.setScope(new String[]{"scope1", "scope2"});

        OAuth2AccessTokenRespDTO tokenRespDTO = handler.issue(tokReqMsgCtx);
        assertNotNull(tokenRespDTO.getAccessToken());
        PrivilegedCarbonContext.endTenantFlow();
    }

    @DataProvider(name = "AuthorizeAccessDelegationDataProvider")
    public Object[][] buildAuthorizeAccessDelegationDataProvider() {

        return new Object[][]{{GrantType.SAML20_BEARER.toString()}, {GrantType.IWA_NTLM.toString()},
                {PASSWORD_GRANT}};
    }

    @Test(dataProvider = "AuthorizeAccessDelegationDataProvider")
    public void testAuthorizeAccessDelegation(String grantType) throws Exception {

        Set<OAuthCallbackHandlerMetaData> callbackHandlerMetaData = new HashSet<>();
        callbackHandlerMetaData.add(new OAuthCallbackHandlerMetaData(DEFAULT_CALLBACK_HANDLER_CLASS_NAME, null, 1));

        //        OAuthCallbackManager oAuthCallbackManager = new OAuthCallbackManager();
        //        Field field = AbstractAuthorizationGrantHandler.class.getDeclaredField("callbackManager");
        //        field.setAccessible(true);
        //        field.set(handler, oAuthCallbackManager);
        //        field.setAccessible(false);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId(clientId);
        oAuth2AccessTokenReqDTO.setGrantType(grantType);

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(new String[]{"scope1", "scope2"});
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        boolean result = handler.authorizeAccessDelegation(tokReqMsgCtx);
        assertTrue(result);
    }

    @DataProvider(name = "IsAuthorizedClientDataProvider")
    public Object[][] buildIsAuthorizedClient() {

        return new Object[][]{
                {true, GrantType.SAML20_BEARER.toString() + " " + GrantType.IWA_NTLM.toString() + " " + PASSWORD_GRANT,
                        PASSWORD_GRANT, true},
                {true, GrantType.SAML20_BEARER.toString() + " " + GrantType.IWA_NTLM.toString(), PASSWORD_GRANT,
                        false}, {true, null, PASSWORD_GRANT, false}, {false, null, PASSWORD_GRANT, false}};
    }

    @Test(dataProvider = "IsAuthorizedClientDataProvider")
    public void testIsAuthorizedClient(boolean oAuthAppDOAvailable, String grantTypes, String grantType, boolean result)
            throws Exception {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId(clientId);
        oAuth2AccessTokenReqDTO.setGrantType(grantType);

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        tokReqMsgCtx.setScope(new String[]{"scope1", "scope2"});
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        if (oAuthAppDOAvailable) {
            OAuthAppDO oAuthAppDO = new OAuthAppDO();
            oAuthAppDO.setGrantTypes(grantTypes);
            tokReqMsgCtx.addProperty("OAuthAppDO", oAuthAppDO);
        }

        assertEquals(handler.isAuthorizedClient(tokReqMsgCtx), result);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testStoreAccessToken() throws IdentityException {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        AccessTokenDO newAccessTokenDO = new AccessTokenDO();
        AccessTokenDO existingAccessTokenDO = new AccessTokenDO();
        newAccessTokenDO.setAuthzUser(authenticatedUser);
        newAccessTokenDO.setScope(new String[]{"scope1", "scope2"});

        handler.storeAccessToken(oAuth2AccessTokenReqDTO, TestConstants.USERSTORE_DOMAIN, newAccessTokenDO,
                TestConstants.NEW_ACCESS_TOKEN, existingAccessTokenDO);

        verify(handler).storeAccessToken(oAuth2AccessTokenReqDTO, TestConstants.USERSTORE_DOMAIN, newAccessTokenDO,
                TestConstants.NEW_ACCESS_TOKEN, existingAccessTokenDO);
        handler.storeAccessToken(oAuth2AccessTokenReqDTO, TestConstants.USERSTORE_DOMAIN, newAccessTokenDO,
                TestConstants.NEW_ACCESS_TOKEN, existingAccessTokenDO);
    }

    @DataProvider(name = "BuildTokenRequestMessageContext")
    public Object[][] buildAttributeValues() {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO1 = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO1.setGrantType(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString());
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext1 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO1);
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO2 = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO2.setGrantType(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString());
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext2 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO2);
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO3 = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO3.setGrantType(CUSTOM_GRANT);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext3 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO3);
        OAuth2ScopeHandler oAuth2ScopeHandler1 = new OAuth2ScopeHandler() {

            @Override
            public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
                return false;
            }

            @Override
            public boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx) {
                return false;
            }
        };
        OAuth2ScopeHandler oAuth2ScopeHandler2 = new OAuth2ScopeHandler() {

            @Override
            public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
                return true;
            }

            @Override
            public boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx) {
                return true;
            }
        };
        OAuth2ScopeHandler oAuth2ScopeHandler3 = new OAuth2ScopeHandler() {

            @Override
            public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
                return false;
            }

            @Override
            public boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx) {
                return true;
            }
        };
        Set<OAuth2ScopeHandler> scopeHandlers = new HashSet<>();
        scopeHandlers.add(null);
        scopeHandlers.add(oAuth2ScopeHandler1);
        scopeHandlers.add(oAuth2ScopeHandler2);
        scopeHandlers.add(oAuth2ScopeHandler3);

        return new Object[][]{{oAuthTokenReqMessageContext1, Collections.EMPTY_SET, true},
                {oAuthTokenReqMessageContext2, Collections.EMPTY_SET, true},
                {oAuthTokenReqMessageContext3, Collections.EMPTY_SET, true},
                {oAuthTokenReqMessageContext3, scopeHandlers, false}};
    }

    @Test(dataProvider = "BuildTokenRequestMessageContext")
    public void testValidateScope(Object tokenRequestMessageContext, Set<OAuth2ScopeHandler> scopeHandlers,
                                  boolean expectedValue) throws IdentityOAuth2Exception {

        OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMessageContext;
        OAuthServerConfiguration serverConfiguration = OAuthServerConfiguration.getInstance();
        serverConfiguration.setOAuth2ScopeHandlers(scopeHandlers);
        tokReqMsgCtx.addProperty(OAUTH_APP_PROPERTY, oAuthAppDO);
        assertEquals(handler.validateScope(tokReqMsgCtx), expectedValue);
    }

    @DataProvider(name = "BuildTokenRequestMsgContextForAuthorizedClient")
    public Object[][] buildTokenRequestMsgContextForAuthorizedClient() {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setGrantType(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString());
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext1 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext2 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext3 = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        OAuthAppDO oAuthAppDO1 = new OAuthAppDO();
        OAuthAppDO oAuthAppDO2 = new OAuthAppDO();
        OAuthAppDO oAuthAppDO3 = new OAuthAppDO();
        oAuthAppDO2.setGrantTypes(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString());
        oAuthAppDO3.setGrantTypes(org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString());
        oAuthTokenReqMessageContext1.addProperty("OAuthAppDO", oAuthAppDO1);
        oAuthTokenReqMessageContext2.addProperty("OAuthAppDO", oAuthAppDO2);
        oAuthTokenReqMessageContext3.addProperty("OAuthAppDO", oAuthAppDO3);

        return new Object[][]{{oAuthTokenReqMessageContext1, false, false},
                {oAuthTokenReqMessageContext1, true, false}, {oAuthTokenReqMessageContext2, false, true},
                {oAuthTokenReqMessageContext2, true, true}, {oAuthTokenReqMessageContext3, false, false},
                {oAuthTokenReqMessageContext3, true, false}};
    }

    @Test(dataProvider = "BuildTokenRequestMsgContextForAuthorizedClient")
    public void testIsAuthorizedClient(Object tokenRequestMsgCtx, boolean debugEnabled, boolean expectedValue)
            throws IdentityOAuth2Exception {
        OAuthTokenReqMessageContext tokReqMsgCtx = (OAuthTokenReqMessageContext) tokenRequestMsgCtx;
        assertEquals(handler.isAuthorizedClient(tokReqMsgCtx), expectedValue);
    }

    @Test(dataProvider = "IssueExistingAccessTokensWithoutConsent")
    public void testIssueExistingAccessTokensWithoutConsent(boolean idpIdColumnEnabled) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(idpIdColumnEnabled);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId(clientId);
        oAuth2AccessTokenReqDTO.setGrantType("client_credential");

        AccessTokenDO existingAccessTokenDO = new AccessTokenDO();
        existingAccessTokenDO.setAuthzUser(authenticatedUser);
        existingAccessTokenDO.setScope(new String[]{"scope1", "scope2"});
        existingAccessTokenDO.setAccessToken("existingAccessToken");
        existingAccessTokenDO.setTokenState(TOKEN_STATE_ACTIVE);
        existingAccessTokenDO.setConsumerKey(clientId);

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        authenticatedUser.setAccessingOrganization("orgabc");
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
        tokReqMsgCtx.setScope(new String[]{"scope1", "scope2"});

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<OAuth2Util> oauth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthTokenPersistenceFactory> factoryMock = mockStatic(OAuthTokenPersistenceFactory.class)) {

            OAuthComponentServiceHolder.getInstance().setActionExecutorService(mockActionExecutionService);

            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(Boolean.TRUE.toString());
            identityUtil.when(() -> IdentityUtil.isTokenLoggable(anyString())).thenCallRealMethod();

            OauthTokenIssuer oauthTokenIssuer = mock(OauthTokenIssuerImpl.class);
            when(oauthTokenIssuer.getAccessTokenType()).thenReturn(OAuth2Constants.TokenTypes.OPAQUE);

            oauth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(clientId)).thenReturn(oauthTokenIssuer);
            oauth2Util.when(() -> OAuth2Util.getAppInformationByClientId(clientId)).thenReturn(oAuthAppDO);
            oauth2Util.when(() -> OAuth2Util.isOrganizationValidAndActive(anyString())).thenReturn(true);
            oauth2Util.when(() -> OAuth2Util.buildScopeString(any())).thenCallRealMethod();
            oauth2Util.when(() -> OAuth2Util.getTokenPartitionedSqlByUserStore(anyString(), any()))
                    .thenCallRealMethod();
            oauth2Util.when(() -> OAuth2Util.getTokenExpireTimeMillis(eq(existingAccessTokenDO), eq(false)))
                    .thenReturn(3600L);

            OAuthCache mockOAuthCache = mock(OAuthCache.class);
            handler.oauthCache = mockOAuthCache;
            doNothing().when(mockOAuthCache).addToCache(any(OAuthCacheKey.class), any(CacheEntry.class));

            OAuthTokenPersistenceFactory mockFactory = mock(OAuthTokenPersistenceFactory.class);
            AccessTokenDAO mockAccessTokenDAO = mock(AccessTokenDAO.class);
            factoryMock.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockFactory);
            when(mockFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
            when(mockAccessTokenDAO.getLatestAccessToken(
                    eq(clientId),
                    eq(authenticatedUser),
                    eq(null),
                    eq("scope1 scope2"),
                    eq("NONE"),
                    eq(false))).thenReturn(existingAccessTokenDO);

            OAuth2AccessTokenRespDTO tokenRespDTO = handler.issue(tokReqMsgCtx);
            assertNotNull(tokenRespDTO.getAccessToken());
            assertEquals(tokenRespDTO.getAccessToken(), existingAccessTokenDO.getAccessToken());
        }
    }

    @DataProvider(name = "IssueExistingAccessTokensWithoutConsent")
    public Object[][] issueExistingAccessTokensWithoutConsent() {

        return new Object[][]{
                {true}, {false}
        };
    }

    private static class MockAuthzGrantHandler extends AbstractAuthorizationGrantHandler {

    }
}
