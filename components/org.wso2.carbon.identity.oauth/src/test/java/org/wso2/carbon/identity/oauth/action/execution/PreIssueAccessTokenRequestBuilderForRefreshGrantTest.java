/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.action.execution;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Header;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.RefreshToken;
import org.wso2.carbon.identity.oauth.action.model.TokenRequest;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.util.ClaimHandlerUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;

public class PreIssueAccessTokenRequestBuilderForRefreshGrantTest {

    private PreIssueAccessTokenRequestBuilder preIssueAccessTokenRequestBuilder;

    private MockedStatic<ClaimHandlerUtil> claimHandlerUtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtils;

    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String TEST_USERNAME = "testUser";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final int TEST_TENANT_ID = 1234;
    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_USER_STORE = "PRIMARY";
    private static final String TEST_URL = "https://test.com/oauth2/token";
    private static final String TEST_AUDIENCE = "audience1";
    private static final long REFRESH_TOKEN_EXPIRY_AT_APP = 84600L;

    @BeforeClass
    public void setUp() {

        preIssueAccessTokenRequestBuilder = new PreIssueAccessTokenRequestBuilder();

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
        doReturn(OAuthConstants.GrantTypes.REFRESH_TOKEN + " " + OAuthConstants.GrantTypes.AUTHORIZATION_CODE).when(
                oAuthAppDO).getGrantTypes();
        doReturn(REFRESH_TOKEN_EXPIRY_AT_APP).when(oAuthAppDO).getRefreshTokenExpiryTime();
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CLIENT_ID, TEST_TENANT_DOMAIN))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getIdTokenIssuer(TEST_TENANT_DOMAIN)).thenReturn(TEST_URL);
        doReturn(new String[]{TEST_AUDIENCE}).when(oAuthAppDO).getAudiences();
        doReturn(TEST_CLIENT_ID).when(oAuthAppDO).getOauthConsumerKey();
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getOIDCAudience(TEST_CLIENT_ID, oAuthAppDO)).
                thenReturn(new LinkedList<>(Collections.singleton(TEST_AUDIENCE)));
        oAuth2UtilMockedStatic.when(OAuth2Util::isPairwiseSubEnabledForAccessTokens).thenReturn(false);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        doReturn(TEST_USER_ID).when(authenticatedUser).getAuthenticatedSubjectIdentifier();

        claimHandlerUtilMockedStatic = mockStatic(ClaimHandlerUtil.class);
        CustomClaimsCallbackHandler customClaimsCallbackHandler = mock(CustomClaimsCallbackHandler.class);
        claimHandlerUtilMockedStatic.when(() -> ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO)).
                thenReturn(customClaimsCallbackHandler);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TEST_TENANT_DOMAIN))
                .thenReturn(TEST_TENANT_ID);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(() -> LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);

        AuthorizationGrantHandler authorizationGrantHandler = mock(AuthorizationGrantHandler.class);
        Map<String, AuthorizationGrantHandler> mockGrantTypesMap = new HashMap<>();
        mockGrantTypesMap.put(OAuthConstants.GrantTypes.REFRESH_TOKEN, authorizationGrantHandler);
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getSupportedGrantTypes()).
                thenReturn(mockGrantTypesMap);
    }

    @AfterClass
    public void tearDown() {

        preIssueAccessTokenRequestBuilder = null;
        oAuth2UtilMockedStatic.close();
        oAuthServerConfiguration.close();
        claimHandlerUtilMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        loggerUtils.close();
    }

    @Test
    public void testGetSupportedActionType() {

        ActionType actionType = preIssueAccessTokenRequestBuilder.getSupportedActionType();
        assertEquals(actionType, ActionType.PRE_ISSUE_ACCESS_TOKEN);
    }

    @Test
    public void testBuildActionExecutionRequest()
            throws ActionExecutionRequestBuilderException {

        ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder.
                buildActionExecutionRequest(
                        FlowContext.create().add("tokenMessageContext", getMockTokenMessageContext()), null);
        Assert.assertNotNull(actionExecutionRequest);
        assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ACCESS_TOKEN);
        assertEvent((PreIssueAccessTokenEvent) actionExecutionRequest.getEvent(), getExpectedEvent());
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations(), getExpectedAllowedOperations());
    }

    private void assertEvent(PreIssueAccessTokenEvent actualEvent, PreIssueAccessTokenEvent expectedEvent) {

        assertEquals(expectedEvent.getTenant().getId(), actualEvent.getTenant().getId());
        assertAccessToken(actualEvent.getAccessToken(), expectedEvent.getAccessToken());
        assertRefreshToken(actualEvent.getRefreshToken(), expectedEvent.getRefreshToken());
        assertRequest((TokenRequest) actualEvent.getRequest(), (TokenRequest) expectedEvent.getRequest());
    }

    private void assertAccessToken(AccessToken actualAccessToken, AccessToken expectedAccessToken) {

        assertEquals(actualAccessToken.getClaims().size(), expectedAccessToken.getClaims().size());
        for (int i = 0; i < expectedAccessToken.getClaims().size(); i++) {
            AccessToken.Claim actualClaim = actualAccessToken.getClaims().get(i);
            AccessToken.Claim expectedClaim = expectedAccessToken.getClaims().get(i);
            assertEquals(actualClaim.getName(), expectedClaim.getName());
            assertEquals(actualClaim.getValue(), expectedClaim.getValue());
        }
        assertEquals(actualAccessToken.getScopes().size(), expectedAccessToken.getScopes().size());
        for (int i = 0; i < expectedAccessToken.getScopes().size(); i++) {
            String actualScope = expectedAccessToken.getScopes().get(i);
            String expectedScope = expectedAccessToken.getScopes().get(i);
            assertEquals(actualScope, expectedScope);
        }
    }

    private void assertRefreshToken(RefreshToken actualRefreshToken, RefreshToken expectedRefreshToken) {

        assertEquals(actualRefreshToken.getClaims().size(), expectedRefreshToken.getClaims().size());
        for (int i = 0; i < expectedRefreshToken.getClaims().size(); i++) {
            RefreshToken.Claim actualClaim = actualRefreshToken.getClaims().get(i);
            RefreshToken.Claim expectedClaim = expectedRefreshToken.getClaims().get(i);
            assertEquals(actualClaim.getName(), expectedClaim.getName());
            assertEquals(actualClaim.getValue(), expectedClaim.getValue());
        }
    }

    private void assertRequest(TokenRequest actualRequest, TokenRequest expectedRequest) {

        assertEquals(actualRequest.getClientId(), expectedRequest.getClientId());
        assertEquals(actualRequest.getGrantType(), expectedRequest.getGrantType());
        assertEquals(actualRequest.getScopes().size(), expectedRequest.getScopes().size());
        for (int i = 0; i < expectedRequest.getScopes().size(); i++) {
            assertEquals(actualRequest.getScopes().get(i), expectedRequest.getScopes().get(i));
        }
        assertEquals(actualRequest.getAdditionalHeaders().size(), expectedRequest.getAdditionalHeaders().size());
        for (int i = 0; i < expectedRequest.getAdditionalHeaders().size(); i++) {
            Header actualAdditionalHeader = actualRequest.getAdditionalHeaders().get(i);
            Header expectedAdditionalHeader = expectedRequest.getAdditionalHeaders().get(i);
            assertEquals(actualAdditionalHeader.getName(), expectedAdditionalHeader.getName());
            assertEquals(actualAdditionalHeader.getValue(), expectedAdditionalHeader.getValue());
        }
        assertEquals(actualRequest.getAdditionalParams().size(), expectedRequest.getAdditionalParams().size());
        for (int i = 0; i < expectedRequest.getAdditionalParams().size(); i++) {
            Param actualAdditionalParam = actualRequest.getAdditionalParams().get(i);
            Param expectedAdditionalParam = expectedRequest.getAdditionalParams().get(i);
            assertEquals(actualAdditionalParam.getName(), expectedAdditionalParam.getName());
            assertEquals(actualAdditionalParam.getValue(), expectedAdditionalParam.getValue());
        }
    }

    private void assertAllowedOperations(List<AllowedOperation> actual, List<AllowedOperation> expected) {

        assertEquals(actual.size(), expected.size());
        for (int i = 0; i < expected.size(); i++) {
            AllowedOperation expectedOperation = expected.get(i);
            AllowedOperation actualOperation = actual.get(i);
            assertEquals(expectedOperation.getOp(), actualOperation.getOp());
            assertEquals(expectedOperation.getPaths().size(), actualOperation.getPaths().size());
            for (int j = 0; j < expectedOperation.getPaths().size(); j++) {
                assertEquals(expectedOperation.getPaths().get(j), actualOperation.getPaths().get(j));
            }
        }
    }

    private OAuthTokenReqMessageContext getMockTokenMessageContext() {

        OAuth2AccessTokenReqDTO tokenReqDTO = mockTokenRequestDTO();
        AuthenticatedUser authenticatedUser = mockAuthenticatedUser();
        return mockMessageContext(tokenReqDTO, authenticatedUser);
    }

    private OAuth2AccessTokenReqDTO mockTokenRequestDTO() {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(TEST_CLIENT_ID);
        tokenReqDTO.setClientSecret(TEST_CLIENT_SECRET);
        tokenReqDTO.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        tokenReqDTO.setTenantDomain(TEST_TENANT_DOMAIN);
        tokenReqDTO.setScope(new String[]{"scope1", "scope2"});
        HttpRequestHeader[] requestHeaders = new HttpRequestHeader[]{
                new HttpRequestHeader("accept", "application/json")
        };
        tokenReqDTO.setHttpRequestHeaders(requestHeaders);
        RequestParameter[] requestParameters = new RequestParameter[]{
                new RequestParameter("grant_type", OAuthConstants.GrantTypes.REFRESH_TOKEN),
                new RequestParameter("refresh_token", "refresh_token"),
                new RequestParameter("scope", "scope1", "scope2"),
                new RequestParameter("client_id", TEST_CLIENT_ID),
                new RequestParameter("client_secret", TEST_CLIENT_SECRET)
        };
        tokenReqDTO.setRequestParameters(requestParameters);
        return tokenReqDTO;
    }

    private AuthenticatedUser mockAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USERNAME);
        authenticatedUser.setUserStoreDomain(TEST_USER_STORE);
        authenticatedUser.setUserId(TEST_USER_ID);
        authenticatedUser.setAuthenticatedSubjectIdentifier(TEST_USER_ID);
        return authenticatedUser;
    }

    private OAuthTokenReqMessageContext mockMessageContext(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                                  AuthenticatedUser authenticatedUser) {

        OAuthTokenReqMessageContext tokenMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenMessageContext.setAuthorizedUser(authenticatedUser);
        tokenMessageContext.setScope(new String[]{"scope1", "scope2"});

        tokenMessageContext.setPreIssueAccessTokenActionsExecuted(false);
        tokenMessageContext.setAudiences(Collections.singletonList(TEST_AUDIENCE));

        tokenMessageContext.addProperty("USER_TYPE", "APPLICATION_USER");
        tokenMessageContext.setValidityPeriod(3600000L);
        return tokenMessageContext;
    }

    private PreIssueAccessTokenEvent getExpectedEvent() {

        PreIssueAccessTokenEvent.Builder eventBuilder = new PreIssueAccessTokenEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(TEST_TENANT_ID), TEST_TENANT_DOMAIN));

        AccessToken.Builder accessTokenBuilder = new AccessToken.Builder();
        accessTokenBuilder
                .addClaim(AccessToken.ClaimNames.ISS.getName(), TEST_URL)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), TEST_CLIENT_ID)
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), "APPLICATION_USER")
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), 3600L)
                .addClaim(AccessToken.ClaimNames.AUD.getName(), new LinkedList<>(Collections.singleton(TEST_AUDIENCE)))
                .addClaim(AccessToken.ClaimNames.SUB.getName(), TEST_USER_ID)
                .scopes(Arrays.asList("scope1", "scope2"));
        eventBuilder.accessToken(accessTokenBuilder.build());

        RefreshToken.Builder refreshTokenBuilder = new RefreshToken.Builder();
        refreshTokenBuilder.addClaim(RefreshToken.ClaimNames.EXPIRES_IN.getName(), REFRESH_TOKEN_EXPIRY_AT_APP);
        eventBuilder.refreshToken(refreshTokenBuilder.build());

        TokenRequest.Builder requestBuilder = new TokenRequest.Builder();
        requestBuilder
                .clientId(TEST_CLIENT_ID)
                .grantType(OAuthConstants.GrantTypes.REFRESH_TOKEN)
                .scopes(Arrays.asList("scope1", "scope2"))
                .addAdditionalHeader("accept", new String[]{"application/json"})
                .addAdditionalParam("grant_type", new String[]{OAuthConstants.GrantTypes.REFRESH_TOKEN})
                .addAdditionalParam("refresh_token", new String[]{"refresh_token"})
                .addAdditionalParam("scope", new String[]{"scope1", "scope2"})
                .addAdditionalParam("client_id", new String[]{TEST_CLIENT_ID})
                .addAdditionalParam("client_secret", new String[]{TEST_CLIENT_SECRET});
        eventBuilder.request(requestBuilder.build());

        return eventBuilder.build();
    }

    private List<AllowedOperation> getExpectedAllowedOperations() {

        List<AllowedOperation> allowedOperations = new ArrayList<>();
        AllowedOperation addOperation = new AllowedOperation();
        addOperation.setOp(Operation.ADD);
        addOperation.setPaths(Arrays.asList(
                "/accessToken/claims/",
                "/accessToken/scopes/",
                "/accessToken/claims/aud/"));
        AllowedOperation removeOperation = new AllowedOperation();
        removeOperation.setOp(Operation.REMOVE);
        removeOperation.setPaths(Arrays.asList(
                "/accessToken/scopes/",
                "/accessToken/claims/aud/"));
        AllowedOperation replaceOperation = new AllowedOperation();
        replaceOperation.setOp(Operation.REPLACE);
        replaceOperation.setPaths(Arrays.asList(
                "/accessToken/scopes/",
                "/accessToken/claims/aud/",
                "/accessToken/claims/expires_in",
                "/refreshToken/claims/expires_in"));
        allowedOperations.add(addOperation);
        allowedOperations.add(removeOperation);
        allowedOperations.add(replaceOperation);

        return allowedOperations;
    }
}
