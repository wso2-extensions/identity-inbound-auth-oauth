/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.RevokedTokenPersistenceDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for HybridRefreshTokenGrantProcessor.
 */
@WithCarbonHome
public class HybridRefreshTokenGrantProcessorTest {

    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_REFRESH_TOKEN = "test_refresh_token";
    private static final String TEST_TOKEN_ID = "test_token_id";
    private static final String TEST_GRANT_TYPE = "authorization_code";
    private static final String TEST_TOKEN_TYPE = "Bearer";
    private static final String TEST_USER_STORE_DOMAIN = "PRIMARY";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String[] TEST_SCOPE = new String[]{"openid", "profile"};

    private HybridRefreshTokenGrantProcessor hybridRefreshTokenGrantProcessor;
    private AutoCloseable closeable;

    @Mock
    private RevokedTokenPersistenceDAO mockRevokedTokenDao;

    @Mock
    private DefaultRefreshTokenGrantProcessor mockDefaultRefreshTokenGrantProcessor;

    @Mock
    private OAuthTokenPersistenceFactory mockOAuthTokenPersistenceFactory;

    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfigMockedStatic;
    private MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactoryMockedStatic;
    private MockedStatic<OIDCClaimUtil> oidcClaimUtilMockedStatic;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        oAuthServerConfigMockedStatic = mockStatic(OAuthServerConfiguration.class);
        oAuthTokenPersistenceFactoryMockedStatic = mockStatic(OAuthTokenPersistenceFactory.class);
        oidcClaimUtilMockedStatic = mockStatic(OIDCClaimUtil.class);

        oAuthServerConfigMockedStatic.when(OAuthServerConfiguration::getInstance)
                .thenReturn(mockOAuthServerConfiguration);
        oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockOAuthTokenPersistenceFactory);
        lenient().when(mockOAuthTokenPersistenceFactory.getRevokedTokenPersistenceDAO())
                .thenReturn(mockRevokedTokenDao);

        // Create processor after static mocks are set up so that the private final revokedTokenDao
        // field is initialized with the mock from OAuthTokenPersistenceFactory.
        hybridRefreshTokenGrantProcessor = new HybridRefreshTokenGrantProcessor();

        // Inject mock defaultRefreshTokenGrantProcessor using reflection.
        Field defaultProcessorField =
                HybridRefreshTokenGrantProcessor.class.getDeclaredField("defaultRefreshTokenGrantProcessor");
        defaultProcessorField.setAccessible(true);
        defaultProcessorField.set(hybridRefreshTokenGrantProcessor, mockDefaultRefreshTokenGrantProcessor);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeMockSafely(oAuth2UtilMockedStatic);
        closeMockSafely(oAuthServerConfigMockedStatic);
        closeMockSafely(oAuthTokenPersistenceFactoryMockedStatic);
        closeMockSafely(oidcClaimUtilMockedStatic);

        if (closeable != null) {
            closeable.close();
        }
    }

    private void closeMockSafely(MockedStatic<?> mock) {

        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already closed.
            }
        }
    }

    // ======================== validateRefreshToken tests ========================

    @Test
    public void testValidateRefreshToken_WhenValidToken_ShouldReturnValidationData() throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO expectedValidationBean = createRefreshTokenValidationDataDO();

        try (MockedConstruction<HybridPersistenceTokenProvider> providerMock =
                     mockConstruction(HybridPersistenceTokenProvider.class, (mock, context) -> {
                         when(mock.getVerifiedRefreshToken(TEST_REFRESH_TOKEN, TEST_CONSUMER_KEY))
                                 .thenReturn(expectedValidationBean);
                     })) {

            OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
            RefreshTokenValidationDataDO result =
                    hybridRefreshTokenGrantProcessor.validateRefreshToken(tokenReqMessageContext);

            assertNotNull(result);
            assertEquals(result.getRefreshToken(), TEST_REFRESH_TOKEN);
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateRefreshToken_WhenNullValidationBean_ShouldThrowException()
            throws IdentityOAuth2Exception {

        try (MockedConstruction<HybridPersistenceTokenProvider> providerMock =
                     mockConstruction(HybridPersistenceTokenProvider.class, (mock, context) -> {
                         when(mock.getVerifiedRefreshToken(TEST_REFRESH_TOKEN, TEST_CONSUMER_KEY))
                                 .thenReturn(null);
                     })) {

            OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
            hybridRefreshTokenGrantProcessor.validateRefreshToken(tokenReqMessageContext);
        }
    }

    // ======================== persistNewToken tests ========================

    @Test
    public void testPersistNewToken_WhenRenewEnabledAndRefreshPersistenceEnabled_ShouldInvalidateAndCreateNew()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(true);

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        try (MockedConstruction<RefreshTokenDAOImpl> refreshTokenDAOMock =
                     mockConstruction(RefreshTokenDAOImpl.class)) {

            hybridRefreshTokenGrantProcessor.persistNewToken(
                    tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

            RefreshTokenDAOImpl constructedDAO = refreshTokenDAOMock.constructed().get(0);
            verify(constructedDAO).invalidateAndCreateNewRefreshToken(
                    eq(TEST_TOKEN_ID),
                    eq(OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE),
                    eq(TEST_CONSUMER_KEY),
                    eq(accessTokenBean),
                    eq(TEST_USER_STORE_DOMAIN));
        }

        verify(mockRevokedTokenDao, never()).addRevokedToken(anyString(), anyString(), anyLong());
    }

    @Test
    public void testPersistNewToken_WhenRenewEnabledAndRefreshPersistenceDisabled_ShouldAddRevokedToken()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(false);

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        hybridRefreshTokenGrantProcessor.persistNewToken(
                tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockRevokedTokenDao).addRevokedToken(
                eq(TEST_REFRESH_TOKEN),
                eq(TEST_CONSUMER_KEY),
                eq(3600L));
    }

    @Test
    public void testPersistNewToken_WhenRenewDisabledByAppConfig_ShouldNotInvalidateOrRevoke()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("false");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        hybridRefreshTokenGrantProcessor.persistNewToken(
                tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockRevokedTokenDao, never()).addRevokedToken(anyString(), anyString(), anyLong());
    }

    @Test
    public void testPersistNewToken_WhenRenewBlankAndGlobalEnabled_ShouldRevoke()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO(null);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(OAuth2Util::isRefreshTokenPersistenceEnabled).thenReturn(false);
        when(mockOAuthServerConfiguration.isRefreshTokenRenewalEnabled()).thenReturn(true);

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        hybridRefreshTokenGrantProcessor.persistNewToken(
                tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockRevokedTokenDao).addRevokedToken(
                eq(TEST_REFRESH_TOKEN),
                eq(TEST_CONSUMER_KEY),
                eq(3600L));
    }

    @Test
    public void testPersistNewToken_WhenRenewBlankAndGlobalDisabled_ShouldNotRevoke()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO(null);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);
        when(mockOAuthServerConfiguration.isRefreshTokenRenewalEnabled()).thenReturn(false);

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        hybridRefreshTokenGrantProcessor.persistNewToken(
                tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockRevokedTokenDao, never()).addRevokedToken(anyString(), anyString(), anyLong());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testPersistNewToken_WhenOAuthAppNotFound_ShouldThrowException() throws Exception {

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenThrow(new org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException(
                        "not found"));

        OAuthTokenReqMessageContext tokenReqMessageContext = createTokenReqMessageContext();
        RefreshTokenValidationDataDO oldRefreshToken = createRefreshTokenValidationDataDO();
        tokenReqMessageContext.addProperty(OAuth2Constants.PREV_ACCESS_TOKEN, oldRefreshToken);

        AccessTokenDO accessTokenBean = new AccessTokenDO();

        hybridRefreshTokenGrantProcessor.persistNewToken(
                tokenReqMessageContext, accessTokenBean, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);
    }

    // ======================== createAccessTokenBean tests ========================

    @Test
    public void testCreateAccessTokenBean_WhenRenewEnabled_ShouldGenerateNewTokenId()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        tokReqMsgCtx.setAuthorizedUser(createAuthenticatedUser());
        tokReqMsgCtx.setScope(TEST_SCOPE);

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();
        validationBean.setGrantType(TEST_GRANT_TYPE);

        oidcClaimUtilMockedStatic.when(() -> OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(TEST_GRANT_TYPE))
                .thenReturn(true);

        AccessTokenDO result = hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);

        assertNotNull(result);
        assertEquals(result.getConsumerKey(), TEST_CONSUMER_KEY);
        assertEquals(result.getTokenType(), TEST_TOKEN_TYPE);
        assertEquals(result.getTokenState(), OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        assertTrue(result.isNotPersisted());
        // Token id should be a new UUID, not the old one.
        assertNotNull(result.getTokenId());
        assertTrue(!result.getTokenId().equals(TEST_TOKEN_ID));
        assertTrue(result.isConsentedToken());
        assertTrue(tokReqMsgCtx.isConsentedToken());
    }

    @Test
    public void testCreateAccessTokenBean_WhenRenewDisabled_ShouldReuseTokenId()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("false");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        tokReqMsgCtx.setAuthorizedUser(createAuthenticatedUser());
        tokReqMsgCtx.setScope(TEST_SCOPE);

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();
        validationBean.setGrantType(TEST_GRANT_TYPE);

        oidcClaimUtilMockedStatic.when(() -> OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(TEST_GRANT_TYPE))
                .thenReturn(false);

        AccessTokenDO result = hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);

        assertNotNull(result);
        assertEquals(result.getTokenId(), TEST_TOKEN_ID);
    }

    @Test
    public void testCreateAccessTokenBean_WhenPreviousGrantTypeIsRefreshTokenAndConsented_ShouldSetConsented()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        tokReqMsgCtx.setAuthorizedUser(createAuthenticatedUser());
        tokReqMsgCtx.setScope(TEST_SCOPE);

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        validationBean.setConsented(true);

        AccessTokenDO result = hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);

        assertNotNull(result);
        assertTrue(result.isConsentedToken());
        assertTrue(tokReqMsgCtx.isConsentedToken());
    }

    @Test
    public void testCreateAccessTokenBean_WhenPreviousGrantTypeIsRefreshTokenAndNotConsented_ShouldNotSetConsented()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        tokReqMsgCtx.setAuthorizedUser(createAuthenticatedUser());
        tokReqMsgCtx.setScope(TEST_SCOPE);

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();
        validationBean.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        validationBean.setConsented(false);

        AccessTokenDO result = hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);

        assertNotNull(result);
        assertTrue(!result.isConsentedToken());
        assertTrue(!tokReqMsgCtx.isConsentedToken());
    }

    @Test
    public void testCreateAccessTokenBean_WhenPreviousGrantTypeIsNotConsentApplicable_ShouldNotSetConsented()
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = createOAuthAppDO("true");
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenReturn(oAuthAppDO);

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        tokReqMsgCtx.setAuthorizedUser(createAuthenticatedUser());
        tokReqMsgCtx.setScope(TEST_SCOPE);

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();
        validationBean.setGrantType("client_credentials");

        oidcClaimUtilMockedStatic.when(
                        () -> OIDCClaimUtil.isConsentBasedClaimFilteringApplicable("client_credentials"))
                .thenReturn(false);

        AccessTokenDO result = hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);

        assertNotNull(result);
        assertTrue(!result.isConsentedToken());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testCreateAccessTokenBean_WhenOAuthAppNotFound_ShouldThrowException() throws Exception {

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY))
                .thenThrow(new org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException(
                        "not found"));

        OAuthTokenReqMessageContext tokReqMsgCtx = createTokenReqMessageContext();
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();

        hybridRefreshTokenGrantProcessor.createAccessTokenBean(
                tokReqMsgCtx, tokenReq, validationBean, TEST_TOKEN_TYPE);
    }

    // ======================== isLatestRefreshToken tests ========================

    @Test
    public void testIsLatestRefreshToken_ShouldAlwaysReturnTrue() {

        OAuth2AccessTokenReqDTO tokenReq = createOAuth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = createRefreshTokenValidationDataDO();

        boolean result = hybridRefreshTokenGrantProcessor.isLatestRefreshToken(
                tokenReq, validationBean, TEST_USER_STORE_DOMAIN);

        assertTrue(result);
    }

    // ======================== addUserAttributesToCache tests ========================

    @Test
    public void testAddUserAttributesToCache_ShouldDelegateToDefaultProcessor() throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenBean = new AccessTokenDO();
        OAuthTokenReqMessageContext msgCtx = createTokenReqMessageContext();

        hybridRefreshTokenGrantProcessor.addUserAttributesToCache(accessTokenBean, msgCtx);

        verify(mockDefaultRefreshTokenGrantProcessor).addUserAttributesToCache(accessTokenBean, msgCtx);
    }

    // ======================== Helper methods ========================

    private OAuthTokenReqMessageContext createTokenReqMessageContext() {

        OAuth2AccessTokenReqDTO tokenReqDTO = createOAuth2AccessTokenReqDTO();
        return new OAuthTokenReqMessageContext(tokenReqDTO);
    }

    private OAuth2AccessTokenReqDTO createOAuth2AccessTokenReqDTO() {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(TEST_CONSUMER_KEY);
        tokenReqDTO.setRefreshToken(TEST_REFRESH_TOKEN);
        tokenReqDTO.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        return tokenReqDTO;
    }

    private RefreshTokenValidationDataDO createRefreshTokenValidationDataDO() {

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setRefreshToken(TEST_REFRESH_TOKEN);
        validationBean.setTokenId(TEST_TOKEN_ID);
        validationBean.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        validationBean.setGrantType(TEST_GRANT_TYPE);
        validationBean.setScope(TEST_SCOPE);
        return validationBean;
    }

    private OAuthAppDO createOAuthAppDO(String renewRefreshTokenEnabled) {

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setRenewRefreshTokenEnabled(renewRefreshTokenEnabled);
        oAuthAppDO.setRefreshTokenExpiryTime(3600L);
        oAuthAppDO.setAppOwner(createAuthenticatedUser());
        return oAuthAppDO;
    }

    private AuthenticatedUser createAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testuser");
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);
        authenticatedUser.setUserStoreDomain(TEST_USER_STORE_DOMAIN);
        return authenticatedUser;
    }
}
