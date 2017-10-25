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
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.sql.Timestamp;
import java.util.Arrays;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

/**
 * Test class for RefreshGrantHandler test cases.
 */
@PrepareForTest({OAuthServerConfiguration.class, TokenMgtDAO.class, IdentityUtil.class, OAuth2Util.class,
        AbstractAuthorizationGrantHandler.class})
public class RefreshGrantHandlerTest extends PowerMockIdentityBaseTest {

    @Mock
    private TokenMgtDAO mockTokenMgtDAO;
    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    private RefreshGrantHandler refreshGrantHandler;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);

        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
        whenNew(TokenMgtDAO.class).withNoArguments().thenReturn(mockTokenMgtDAO);

        OauthTokenIssuer oauthTokenIssuer = spy(new OauthTokenIssuer() {

            @Override
            public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }
        });

        when(mockOAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
        when(oauthTokenIssuer.accessToken(any(OAuthTokenReqMessageContext.class))).thenReturn("accessToken1");
        when(oauthTokenIssuer.refreshToken(any(OAuthTokenReqMessageContext.class))).thenReturn("refreshToken1");
    }

    @Test(dataProvider = "GetValidateGrantData")
    public void testValidateGrant(String clientId, String refreshToken, String accessToken, String tokenState,
                                  Boolean isUsernameCaseSensitive, Boolean expected) throws Exception {

        mockStatic(OAuth2Util.class);
        RefreshTokenValidationDataDO validationDataDO = constructValidationDataDO(accessToken, tokenState,
                isUsernameCaseSensitive);
        when(mockTokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(validationDataDO);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(isUsernameCaseSensitive);
        when(OAuth2Util.checkTB(any(OAuthTokenReqMessageContext.class),anyString())).thenReturn("");

        if ((StringUtils.equals(tokenState, TOKEN_STATE_EXPIRED) || StringUtils.equals(tokenState,
                TOKEN_STATE_ACTIVE)) && StringUtils.equals(clientId, "clientId2")) {

            AccessTokenDO[] accessTokenDOS = new AccessTokenDO[2];
            accessTokenDOS[0] = new AccessTokenDO();
            accessTokenDOS[0].setTokenState(TOKEN_STATE_ACTIVE);
            accessTokenDOS[0].setRefreshToken("refreshToken1");

            accessTokenDOS[1] = new AccessTokenDO();
            accessTokenDOS[1].setTokenState(TOKEN_STATE_EXPIRED);
            accessTokenDOS[1].setRefreshToken("refreshToken1");

            when(mockTokenMgtDAO.retrieveLatestAccessTokens(anyString(), any(AuthenticatedUser.class), anyString(),
                    anyString(), anyBoolean(), anyInt())).thenReturn(Arrays.asList(accessTokenDOS));

            when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(true);
            when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(true);
        }

        System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken(refreshToken);
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        Boolean actual = refreshGrantHandler.validateGrant(tokenReqMessageContext);
        if (expected) {
            assertEquals(actual, expected, "Refresh token validation should be successful.");
        } else {
            assertEquals(actual, expected, "Refresh token validation should fail.");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForException() throws Exception {

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(true);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(true);

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setAccessToken("accessToken1");
        validationDataDO.setRefreshTokenState(TOKEN_STATE_EXPIRED);
        when(mockTokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(validationDataDO);

        if (validationDataDO.getAuthorizedUser() == null) {
            when(OAuth2Util.getUserStoreForFederatedUser(any(AuthenticatedUser.class))).thenThrow(new
                    IdentityOAuth2Exception("Authenticated user cannot be null."));
        }

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId("clientId");
        tokenReqDTO.setRefreshToken("refreshToken1");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        refreshGrantHandler.validateGrant(tokenReqMessageContext);
        Assert.fail("Authenticated user cannot be null.");
    }

    @Test(dataProvider = "GetTokenIssuerData")
    public void testIssue(Long userAccessTokenExpiryTime, Long validityPeriod, Boolean isValidToken, Boolean
            isRenew, Boolean checkUserNameAssertionEnabled, Boolean checkAccessTokenPartitioningEnabled, Boolean
                                  isUsernameCaseSensitive) throws Exception {

        mockStatic(OAuth2Util.class);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setUserAccessTokenExpiryTime(userAccessTokenExpiryTime);
        oAuthAppDO.setRefreshTokenExpiryTime(userAccessTokenExpiryTime);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(oAuthAppDO);
        when(OAuth2Util.checkUserNameAssertionEnabled()).thenReturn(checkUserNameAssertionEnabled);
        when(OAuth2Util.checkAccessTokenPartitioningEnabled()).thenReturn(checkAccessTokenPartitioningEnabled);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("username");

        when(OAuth2Util.addUsernameToToken(authenticatedUser, "accessToken1")).thenReturn("accessToken1");
        when(OAuth2Util.addUsernameToToken(authenticatedUser, "refreshToken1")).thenReturn("refreshToken1");

        RefreshTokenValidationDataDO validationDataDO =
                constructValidationDataDO("accessToken1", TOKEN_STATE_EXPIRED, isUsernameCaseSensitive);
        when(mockTokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(validationDataDO);
        doNothing().when(mockTokenMgtDAO)
                .invalidateAndCreateNewToken(anyString(), anyString(), anyString(), anyString(),
                        any(AccessTokenDO.class), anyString());

        if (isValidToken) {
            when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(new Long(5000));
        } else {
            when(OAuth2Util.calculateValidityInMillis(anyLong(), anyLong())).thenReturn(new Long(0));
        }
        when(mockOAuthServerConfiguration.isRefreshTokenRenewalEnabled()).thenReturn(isRenew);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(isUsernameCaseSensitive);

        System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId("clientId1");
        tokenReqDTO.setRefreshToken("refreshToken1");

        RefreshTokenValidationDataDO oldAccessToken = new RefreshTokenValidationDataDO();
        oldAccessToken.setTokenId("tokenId");
        oldAccessToken.setAccessToken("oldAccessToken");

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.addProperty("previousAccessToken", oldAccessToken);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);
        tokenReqMessageContext.setValidityPeriod(validityPeriod);

        OAuth2AccessTokenRespDTO actual = refreshGrantHandler.issue(tokenReqMessageContext);
        if (!actual.isError()) {
            assertEquals(actual.getRefreshToken(), tokenReqDTO.getRefreshToken(), "Token issuance should be " +
                    "successful and the response should contain the valid refresh token.");
        } else {
            assertEquals(actual.getErrorCode(), OAuthError.TokenResponse.INVALID_REQUEST, "Should receive " +
                    "error response for invalid refresh token.");
        }
    }

    @Test(dataProvider = "GetValidateScopeData")
    public void validateScope(String[] requestedScopes, String[] grantedScopes, Boolean expected, String message)
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setScope(requestedScopes);
        tokenReqDTO.setClientId("clientId1");
        tokenReqDTO.setRefreshToken("refreshToken1");
        tokenReqDTO.setGrantType("refreshTokenGrant");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.setScope(grantedScopes);

        System.setProperty(CarbonBaseConstants.CARBON_HOME, "");
        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();
        Boolean actual = refreshGrantHandler.validateScope(tokenReqMessageContext);
        assertEquals(actual, expected, message);
    }

    @DataProvider(name = "GetValidateGrantData")
    public Object[][] ValidateGrantData() {

        return new Object[][]{
                {"clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_ACTIVE, false, true},
                {"clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_INACTIVE, false, false},
                {"clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_EXPIRED, false, false},
                {"clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_EXPIRED, true, false},
                {"clientId2", "refreshToken1", "accessToken1", TOKEN_STATE_EXPIRED, true, true},
                {"clientId2", "refreshToken1", "accessToken1", TOKEN_STATE_ACTIVE, true, true},
                {"clientId2", "refreshToken2", "accessToken1", TOKEN_STATE_EXPIRED, true, false},
                {"clientId1", "refreshToken1", null, null, false, false},
                {"clientId1", "refreshToken1", "accessToken1", null, false, false}
        };
    }

    @DataProvider(name = "GetTokenIssuerData")
    public Object[][] TokenIssuerData() {

        return new Object[][]{
                {0L, UNASSIGNED_VALIDITY_PERIOD, true, true, true, false, false},
                {20L, UNASSIGNED_VALIDITY_PERIOD, true, true, false, true, false},
                {20L, 20L, true, false, true, true, true},
                {0L, UNASSIGNED_VALIDITY_PERIOD, false, false, true, false, false}
        };
    }

    @DataProvider(name = "GetValidateScopeData")
    public Object[][] ValidateScopeData() {

        String[] requestedScopes = new String[2];
        requestedScopes[0] = "scope1";
        requestedScopes[1] = "scope2";

        String[] grantedScopes = new String[1];
        grantedScopes[0] = "scope1";

        String[] grantedScopesWithRequestedScope = new String[1];
        grantedScopesWithRequestedScope[0] = "scope1";
        grantedScopesWithRequestedScope[0] = "scope2";

        return new Object[][]{
                {requestedScopes, grantedScopes, false, "scope validation should fail."},
                {requestedScopes, grantedScopesWithRequestedScope, false, "scope validation should fail."},
                {requestedScopes, new String[0], false, "scope validation should fail."},
                {new String[0], grantedScopes, false, "scope validation should fail."},
        };
    }

    private RefreshTokenValidationDataDO constructValidationDataDO(String accessToken, String refreshTokenState,
                                                                   Boolean isUsernameCaseSensitive) {

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setAccessToken(accessToken);
        validationDataDO.setRefreshTokenState(refreshTokenState);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        if (isUsernameCaseSensitive) {
            authenticatedUser.setUserName("UserName");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/UserName");
        } else {
            authenticatedUser.setUserName("username");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/username");
        }
        authenticatedUser.setFederatedUser(true);
        validationDataDO.setAuthorizedUser(authenticatedUser);
        validationDataDO.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        validationDataDO.setValidityPeriodInMillis(10000);
        return validationDataDO;
    }
}
