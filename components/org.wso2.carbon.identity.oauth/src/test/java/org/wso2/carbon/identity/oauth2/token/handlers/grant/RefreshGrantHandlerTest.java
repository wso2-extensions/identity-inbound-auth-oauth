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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponent;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.test.common.testng.utils.MockAuthenticatedUser;
import org.wso2.carbon.identity.testutil.Whitebox;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.testng.Assert.*;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.*;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

/**
 * Test class for RefreshGrantHandler test cases.
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = { OAuthComponentServiceHolder.class,
        ApplicationManagementServiceComponentHolder.class })
@WithH2Database(files = { "dbScripts/identity.sql" })
public class RefreshGrantHandlerTest {

    private static final String TEST_CLIENT_ID = "SDSDSDS23131231";
    private static final String TEST_USER_ID = "testUser";
    private static final String TEST_USER_DOMAIN = "testDomain";
    private RefreshGrantHandler refreshGrantHandler;
    private AuthenticatedUser authenticatedUser;
    private String[] scopes;

    @BeforeClass
    protected void setUp() throws Exception {
        OAuth2ServiceComponentHolder.setApplicationMgtService(ApplicationManagementServiceImpl.getInstance());
        authenticatedUser = new MockAuthenticatedUser(TEST_USER_ID);
        authenticatedUser.setUserStoreDomain(TEST_USER_DOMAIN);
        scopes = new String[] { "scope1", "scope2" };
    }

    @BeforeMethod
    protected void setUpMethod() throws Exception {
        ApplicationManagementServiceComponent applicationManagementServiceComponent = new ApplicationManagementServiceComponent();
        Whitebox.invokeMethod(applicationManagementServiceComponent, "buildFileBasedSPList", null);
    }

    @DataProvider(name = "GetValidateGrantData")
    public Object[][] validateGrantData() {

        return new Object[][] { { "clientId1", TOKEN_STATE_ACTIVE, false }, { "clientId2", TOKEN_STATE_EXPIRED, true },
                { "clientId2", TOKEN_STATE_ACTIVE, true } };
    }

    @Test(dataProvider = "GetValidateGrantData")
    public void testValidateGrant(String clientId, String tokenState, boolean isUsernameCaseSensitive)
            throws Exception {

        RefreshTokenValidationDataDO validationDataDO = constructValidationDataDO("accessToken1", tokenState,
                isUsernameCaseSensitive);
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        oAuthAppDAO.removeConsumerApplication(clientId);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);

        oAuthAppDAO.addOAuthApplication(oAuthAppDO);

        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        AccessTokenDO[] accessTokenDOS = new AccessTokenDO[2];
        accessTokenDOS[0] = new AccessTokenDO();
        accessTokenDOS[0].setTokenId(UUID.randomUUID().toString());
        accessTokenDOS[0].setConsumerKey(clientId);
        accessTokenDOS[0].setAuthzUser(authenticatedUser);
        accessTokenDOS[0].setTokenState(TOKEN_STATE_ACTIVE);
        accessTokenDOS[0].setRefreshToken("refreshToken1");
        accessTokenDOS[0].setScope(scopes);
        accessTokenDOS[0].setIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDOS[0].setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));

        accessTokenDOS[1] = new AccessTokenDO();
        accessTokenDOS[1].setTokenId(UUID.randomUUID().toString());
        accessTokenDOS[1].setConsumerKey(clientId);
        accessTokenDOS[1].setAuthzUser(authenticatedUser);
        accessTokenDOS[1].setTokenState(tokenState);
        accessTokenDOS[1].setRefreshToken("refreshToken1");
        accessTokenDOS[1].setScope(scopes);
        accessTokenDOS[1].setIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDOS[1].setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));
        tokenMgtDAO.storeAccessToken("accessToken", clientId, accessTokenDOS[0], (AccessTokenDO) null, "PRIMARY");
        tokenMgtDAO.storeAccessToken("accessToken", clientId, accessTokenDOS[1], accessTokenDOS[0], "PRIMARY");

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken("refreshToken1");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        boolean isValid = refreshGrantHandler.validateGrant(tokenReqMessageContext);
        assertTrue(isValid, "Refresh token validation should be successful.");
    }

    @DataProvider(name = "validateGrantExceptionData")
    public Object[][] validateGrantExceptionData() {

        List<AccessTokenDO> accessTokenDOS = new ArrayList<>();
        AccessTokenDO accessTokenDO1 = new AccessTokenDO();
        accessTokenDO1.setTokenState(TOKEN_STATE_ACTIVE);
        accessTokenDO1.setRefreshToken("refreshToken1");

        AccessTokenDO accessTokenDO2 = new AccessTokenDO();
        accessTokenDO2.setTokenState(TOKEN_STATE_EXPIRED);
        accessTokenDO2.setRefreshToken("refreshToken2");

        accessTokenDOS.add(accessTokenDO1);
        accessTokenDOS.add(accessTokenDO2);

        return new Object[][] { { "clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_INACTIVE, accessTokenDOS },
                { "clientId1", "refreshToken3", "accessToken1", TOKEN_STATE_EXPIRED, accessTokenDOS },
                { "clientId1", "refreshToken3", "accessToken1", TOKEN_STATE_EXPIRED, null },
                { "clientId1", "refreshToken1", null, null, accessTokenDOS }, };
    }

    @Test(dataProvider = "validateGrantExceptionData", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForException(String clientId, String refreshToken, String accessToken,
            String tokenState, Object accessTokenObj) throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken(refreshToken);
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        refreshGrantHandler.validateGrant(tokenReqMessageContext);
        Assert.fail("Authenticated user cannot be null.");
    }

    @Test(dataProvider = "GetTokenIssuerData")
    public void testIssue(Long userAccessTokenExpiryTime, Long validityPeriod, boolean isValidToken, boolean isRenew,
                          boolean checkUserNameAssertionEnabled, boolean checkAccessTokenPartitioningEnabled,
                          boolean isUsernameCaseSensitive, String renewRefreshToken, String clientId) throws Exception {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        oAuthAppDAO.removeConsumerApplication(clientId);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setUserAccessTokenExpiryTime(userAccessTokenExpiryTime);
        oAuthAppDO.setRefreshTokenExpiryTime(userAccessTokenExpiryTime);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
        oAuthAppDO.setRenewRefreshTokenEnabled(renewRefreshToken);
        oAuthAppDAO.addOAuthApplication(oAuthAppDO);

        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        AccessTokenDO accessTokenDO1 = new AccessTokenDO();
        accessTokenDO1.setTokenId(clientId);
        accessTokenDO1.setTokenState(TOKEN_STATE_ACTIVE);
        accessTokenDO1.setRefreshToken("refreshToken1");
        accessTokenDO1.setAuthzUser(authenticatedUser);
        accessTokenDO1.setScope(scopes);
        accessTokenDO1.setIssuedTime(new Timestamp(System.currentTimeMillis()));
        accessTokenDO1.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis()));

        tokenMgtDAO.storeAccessToken("accessToken", clientId, accessTokenDO1, (AccessTokenDO) null, "PRIMARY");

        RefreshTokenValidationDataDO validationDataDO = constructValidationDataDO("accessToken1", TOKEN_STATE_EXPIRED,
                isUsernameCaseSensitive);

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken("refreshToken1");
        tokenReqDTO.setScope(scopes);

        RefreshTokenValidationDataDO oldAccessToken = new RefreshTokenValidationDataDO();
        oldAccessToken.setTokenId("tokenId");
        oldAccessToken.setAccessToken("oldAccessToken");

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.addProperty("previousAccessToken", oldAccessToken);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);
        tokenReqMessageContext.setValidityPeriod(validityPeriod);
        tokenReqMessageContext.setScope(scopes);

        OAuth2AccessTokenRespDTO actual = refreshGrantHandler.issue(tokenReqMessageContext);
        assertTrue(!actual.isError());
        assertNotNull(actual.getRefreshToken());
        if (Objects.equals(renewRefreshToken, "true") || (renewRefreshToken == null)) {
            assertNotEquals("refreshToken1", actual.getRefreshToken());
        } else {
            assertEquals("refreshToken1", actual.getRefreshToken());
        }
    }

    @Test(dataProvider = "GetValidateScopeData")
    public void validateScope(String[] requestedScopes, String[] grantedScopes, boolean expected, String message)
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setScope(requestedScopes);
        tokenReqDTO.setClientId("clientId1");
        tokenReqDTO.setRefreshToken("refreshToken1");
        tokenReqDTO.setGrantType("refreshTokenGrant");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.setScope(grantedScopes);

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();
        boolean actual = refreshGrantHandler.validateScope(tokenReqMessageContext);
        assertEquals(actual, expected, message);
    }

    @DataProvider(name = "GetTokenIssuerData")
    public Object[][] tokenIssuerData() {

        return new Object[][] { { 0L, UNASSIGNED_VALIDITY_PERIOD, true, true, true, false, false, "true", "clientId1" },
                { 20L, UNASSIGNED_VALIDITY_PERIOD, true, true, false, true, false, "true", "clientId2" },
                { 20L, 20L, true, false, true, true, true, "true", "clientId3" },
                { 0L, UNASSIGNED_VALIDITY_PERIOD, false, false, true, false, false, "true", "clientId4" },
                { 20L, 20L, true, false, true, true, true, "false", "clientId5" },
                { 20L, 20L, true, false, true, true, true, null, "clientId6" },
                { 20L, 20L, true, false, true, true, true, "true", "clientId7" } };
    }

    @DataProvider(name = "GetValidateScopeData")
    public Object[][] validateScopeData() {

        String[] requestedScopes = new String[2];
        requestedScopes[0] = "scope1";
        requestedScopes[1] = "scope2";

        String[] grantedScopes = new String[1];
        grantedScopes[0] = "scope1";

        String[] grantedScopesWithRequestedScope = new String[1];
        grantedScopesWithRequestedScope[0] = "scope1";
        grantedScopesWithRequestedScope[0] = "scope2";

        return new Object[][] { { requestedScopes, grantedScopes, false, "scope validation should fail." },
                { requestedScopes, grantedScopesWithRequestedScope, false, "scope validation should fail." },
                { requestedScopes, new String[0], false, "scope validation should fail." },
                { new String[] { "scope_not_granted" }, grantedScopes, false, "scope validation should fail." }, };
    }

    private RefreshTokenValidationDataDO constructValidationDataDO(String accessToken, String refreshTokenState,
                                                                   boolean isUsernameCaseSensitive) {

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
