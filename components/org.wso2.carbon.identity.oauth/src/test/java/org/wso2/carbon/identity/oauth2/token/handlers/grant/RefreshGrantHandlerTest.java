/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultOAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultRefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenBindingMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.test.common.testng.utils.MockAuthenticatedUser;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerClientException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_ID;

/**
 * Unit tests for the RefreshGrantHandler class.
 */
@WithCarbonHome
public class RefreshGrantHandlerTest {

    private RefreshTokenGrantProcessor refreshTokenGrantProcessor;
    private OAuthTokenReqMessageContext oAuthTokenReqMessageContext;
    private RefreshTokenValidationDataDO refreshTokenValidationDataDO;
    private OAuthServerConfiguration oAuthServerConfiguration;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private OAuth2ServiceComponentHolder oAuth2ServiceComponentHolder;
    private AuthorizationDetailsService authorizationDetailsService;
    private OAuthAppDO oAuthAppDO;

    @BeforeMethod
    public void init() {
        refreshTokenGrantProcessor = mock(DefaultRefreshTokenGrantProcessor.class);
        oAuthTokenReqMessageContext = mock(OAuthTokenReqMessageContext.class);
        refreshTokenValidationDataDO = mock(RefreshTokenValidationDataDO.class);
        oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuth2AccessTokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        oAuth2ServiceComponentHolder = mock(OAuth2ServiceComponentHolder.class);
        authorizationDetailsService = mock(AuthorizationDetailsService.class);
        oAuthAppDO = mock(OAuthAppDO.class);
    }

    @DataProvider(name = "validateGrantWhenUserIsLockedInUserStoreEnd")
    public Object[][] validateGrantWhenUserIsLockedInUserStoreEnd() {

        String userStoreDomain = "user-store-domain";
        String tenantDomain = "tenant-domain";
        String username = "user";
        MockAuthenticatedUser user1 = new MockAuthenticatedUser(username);
        user1.setUserStoreDomain(userStoreDomain);
        user1.setTenantDomain(tenantDomain);

        MockAuthenticatedUser user2 = new MockAuthenticatedUser(username);

        String subjectIdentifier = "subject-identifier";
        String federatedUserId = "federated-user-id";
        String federatedIDPName = "federated-idp";
        MockAuthenticatedUser federatedUser = new MockAuthenticatedUser(federatedUserId);
        federatedUser.setAuthenticatedSubjectIdentifier(subjectIdentifier);
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(federatedIDPName);

        return new Object[][] {
                {user1, null, null, false, null, false},
                {user1, null, null, false, null, true},
                {user1, null, null, true, null, true},
                {federatedUser, null, null, false, null, true},
                {federatedUser, user1, null, false, null, true},
                {federatedUser, user1, null, true, null, true},
                {federatedUser, user1, new FederatedAssociationManagerClientException("test error"), true, null, true},
                {federatedUser, user1, new FrameworkClientException("test error"), true, null, true},
                {federatedUser, user1, new FederatedAssociationManagerException("test error"), true, null, true},
                {federatedUser, user1, new FrameworkException("test error"), true, null, true},
                {federatedUser, user1, null, true, new AccountLockServiceException("test error"), true},
                {null, null, null, false, null, true},
                {user2, null, null, false, null, true}
        };
    }

    /**
     * Test scenarios for the `validateGrant` method when the user, locked at the user store level,
     * attempts to use the refresh grant.
     *
     * @param user                                       The user attempts to use the refresh grant.
     * @param associatedUser                             Associated local user if the user is federated user.
     * @param federatedAssociationManagerException       Exception when resolving the local associated user.
     * @param isUserLocked                               Whether the user is locked from user store end.
     * @param accountLockServiceException                Exception when checking the account lock status.
     * @param isValidateAuthenticatedUserForRefreshGrant Whether the `ValidateAuthenticatedUserForRefreshGrant`
     *                                                   config is enabled in identity.xml.
     * @throws Exception Any uncaught exception thrown while running the test case.
     */
    @Test(dataProvider = "validateGrantWhenUserIsLockedInUserStoreEnd")
    public void testValidateGrantWhenUserIsLockedInUserStoreEnd(AuthenticatedUser user,
                                                                AuthenticatedUser associatedUser,
                                                                Throwable federatedAssociationManagerException,
                                                                boolean isUserLocked,
                                                                Throwable accountLockServiceException,
                                                                boolean isValidateAuthenticatedUserForRefreshGrant)
            throws Exception {

        when(refreshTokenGrantProcessor.validateRefreshToken(any())).thenReturn(refreshTokenValidationDataDO);
        when(refreshTokenValidationDataDO.getAuthorizedUser()).thenReturn(user);
        when(refreshTokenGrantProcessor.isLatestRefreshToken(any(), any(), any())).thenReturn(true);
        when(oAuthServerConfiguration.isValidateAuthenticatedUserForRefreshGrantEnabled()).thenReturn(
                isValidateAuthenticatedUserForRefreshGrant);
        when(oAuth2ServiceComponentHolder.getRefreshTokenGrantProcessor()).thenReturn(refreshTokenGrantProcessor);
        when(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(authorizationDetailsService
                .getUserConsentedAuthorizationDetails(any(AuthenticatedUser.class), anyString(), anyInt()))
                .thenReturn(new AuthorizationDetails());
        when(oAuth2ServiceComponentHolder.getAuthorizationDetailsService()).thenReturn(authorizationDetailsService);

        FederatedAssociationManager federatedAssociationManager = mock(FederatedAssociationManager.class);
        if (federatedAssociationManagerException instanceof FederatedAssociationManagerException) {
            when(federatedAssociationManager.getUserForFederatedAssociation(anyString(),
                    eq(user.getFederatedIdPName()), eq(user.getAuthenticatedSubjectIdentifier()))).thenThrow(
                    federatedAssociationManagerException);
        } else if (associatedUser != null) {
            when(federatedAssociationManager.getUserForFederatedAssociation(anyString(),
                    eq(user.getFederatedIdPName()), eq(user.getAuthenticatedSubjectIdentifier()))).thenReturn(
                    associatedUser.getUserName());
        }

        AccountLockService accountLockService = mock(AccountLockService.class);
        if (accountLockServiceException != null) {
            when(accountLockService.isAccountLocked(anyString(), anyString())).thenThrow(
                    accountLockServiceException);
        } else {
            when(accountLockService.isAccountLocked(anyString(), anyString())).thenReturn(isUserLocked);
        }

        refreshTokenValidationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        try {
            try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic = mockStatic(
                    OAuthServerConfiguration.class);
                 MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic = mockStatic(
                         OAuth2ServiceComponentHolder.class);
                 MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
                 MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {
                oAuth2Util.when(() -> OAuth2Util.getTenantId(anyString())).thenReturn(TENANT_ID);
                oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                        .thenReturn(oAuthServerConfiguration);
                oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance)
                        .thenReturn(oAuth2ServiceComponentHolder);
                oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getAccountLockService)
                        .thenReturn(accountLockService);
                if (federatedAssociationManagerException instanceof FrameworkException) {
                    frameworkUtilsMockedStatic.when(FrameworkUtils::getFederatedAssociationManager)
                            .thenThrow(federatedAssociationManagerException);
                } else {
                    frameworkUtilsMockedStatic.when(FrameworkUtils::getFederatedAssociationManager)
                            .thenReturn(federatedAssociationManager);
                }

                RefreshGrantHandler refreshGrantHandler = new RefreshGrantHandler();
                refreshGrantHandler.init();
                boolean validateResult = refreshGrantHandler.validateGrant(oAuthTokenReqMessageContext);
                assertTrue(validateResult);
            }
        } catch (IdentityOAuth2Exception e) {
            if (federatedAssociationManagerException != null) {
                assertEquals(ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getCode(), e.getErrorCode());
            } else if (accountLockServiceException != null) {
                assertEquals(ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS.getCode(), e.getErrorCode());
            } else if (isUserLocked) {
                assertEquals(UserCoreConstants.ErrorCode.USER_IS_LOCKED, e.getErrorCode());
            } else {
                fail("Unexpected exception is thrown.");
            }
        }
    }

    @DataProvider(name = "ssoSessionInactiveDataProvider")
    public Object[][] ssoSessionInactiveDataProvider() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "ssoSessionInactiveDataProvider",
            description = "Ensure the refresh grant flow fails for an SSO session-bound token if the corresponding " +
                    "session has expired, even with a valid refresh token.")
    public void testValidateGrantForSSOSessionBoundTokenWithInactiveSession(boolean isTokenRevocationEnabled)
            throws Exception {

        when(refreshTokenGrantProcessor.validateRefreshToken(any())).thenReturn(refreshTokenValidationDataDO);
        when(refreshTokenValidationDataDO.getAuthorizedUser()).thenReturn(new MockAuthenticatedUser("test_user"));
        when(refreshTokenGrantProcessor.isLatestRefreshToken(any(), any(), any())).thenReturn(true);
        when(oAuthServerConfiguration.isValidateAuthenticatedUserForRefreshGrantEnabled()).thenReturn(false);
        when(oAuth2ServiceComponentHolder.getRefreshTokenGrantProcessor()).thenReturn(refreshTokenGrantProcessor);
        when(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn("test_client_id");
        when(refreshTokenValidationDataDO.getTokenBindingReference()).thenReturn("sso_binding_ref");
        when(refreshTokenValidationDataDO.getTokenId()).thenReturn("sso_token_id");
        when(refreshTokenValidationDataDO.getAccessToken()).thenReturn("test_access_token");
        when(refreshTokenValidationDataDO.getRefreshTokenState())
                .thenReturn(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);

        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingReference("sso_binding_ref");
        tokenBinding.setBindingType(OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER);
        tokenBinding.setBindingValue("sso_binding_value");

        TokenBindingMgtDAO tokenBindingMgtDAO = mock(TokenBindingMgtDAO.class);
        when(tokenBindingMgtDAO.getTokenBindingByBindingRef(anyString(), anyString()))
                .thenReturn(Optional.of(tokenBinding));

        OAuthTokenPersistenceFactory oAuthTokenPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
        when(oAuthTokenPersistenceFactory.getTokenBindingMgtDAO()).thenReturn(tokenBindingMgtDAO);

        when(oAuthAppDO.getTokenBindingType())
                .thenReturn(OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER);
        when(oAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()).thenReturn(isTokenRevocationEnabled);

        DefaultOAuth2RevocationProcessor revocationProcessor = mock(DefaultOAuth2RevocationProcessor.class);

        try (MockedStatic<OAuthTokenPersistenceFactory> oAuthTokenPersistenceFactoryMockedStatic =
                     mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolderMockedStatic =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
             MockedStatic<OAuthUtil> oAuthUtilMockedStatic = mockStatic(OAuthUtil.class)) {

            oAuthTokenPersistenceFactoryMockedStatic.when(OAuthTokenPersistenceFactory::getInstance)
                    .thenReturn(oAuthTokenPersistenceFactory);

            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getTenantId(anyString())).thenReturn(TENANT_ID);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(anyString()))
                    .thenReturn(oAuthAppDO);

            oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oAuthServerConfiguration);

            oAuth2ServiceComponentHolderMockedStatic.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(oAuth2ServiceComponentHolder);

            frameworkUtilsMockedStatic.when(() -> FrameworkUtils.getSessionContextFromCache(anyString(), anyString()))
                    .thenReturn(null);
            if (isTokenRevocationEnabled) {
                AccessTokenDO accessTokenDO = mock(AccessTokenDO.class);
                oAuth2UtilMockedStatic
                        .when(() -> OAuth2Util.getAccessTokenDOFromTokenIdentifier(anyString(), eq(true)))
                        .thenReturn(accessTokenDO);
                when(oAuth2ServiceComponentHolder.getRevocationProcessor()).thenReturn(revocationProcessor);
            }

            RefreshGrantHandler refreshGrantHandler = new RefreshGrantHandler();
            refreshGrantHandler.init();

            try {
                refreshGrantHandler.validateGrant(oAuthTokenReqMessageContext);
                fail("Expected exception was not thrown.");
            } catch (IdentityOAuth2Exception e) {
                if (isTokenRevocationEnabled) {
                    verify(revocationProcessor, times(1)).revokeAccessToken(
                            any(), any(AccessTokenDO.class));
                } else {
                    verify(revocationProcessor, never()).revokeAccessToken(any(), any());
                }
            }
        }
    }
}
