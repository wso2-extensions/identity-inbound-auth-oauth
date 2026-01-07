/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action.execution.versioning.v1;

import org.apache.commons.codec.binary.Base64;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Header;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.management.api.model.Action;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.TokenRequest;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.util.ClaimHandlerUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

/**
 * Unit test class for PreIssueAccessTokenRequestBuilder class.
 */
public class PreIssueAccessTokenRequestBuilderV1Test {

    @Mock
    OrganizationManager mockOrganizationManager;

    @Mock
    OAuthComponentServiceHolder mockOAuthComponentServiceHolder;

    private static final String ORG_NAME = "test.com";
    private static final String ORG_ID = "2364283-349o34nnv-92713972nx";
    private static final String ORG_HANDLE = "testhandle";
    private static final int ORG_DEPTH = 1;
    private PreIssueAccessTokenRequestBuilder preIssueAccessTokenRequestBuilder;

    private MockedStatic<ClaimHandlerUtil> claimHandlerUtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtils;

    private static final String CLIENT_ID_TEST = "test-client-id";
    private static final String CLIENT_SECRET_TEST = "test-client-secret";
    private static final String GRANT_TYPE_TEST = "password";
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = 1234;
    private static final String USER_ID_TEST = "user-123";
    private static final String USERNAME_TEST = "testUser";
    private static final String PASSWORD_TEST = "test@123";
    private static final String USER_STORE_TEST = "PRIMARY";
    private static final String TEST_URL = "https://test.com/oauth2/token";
    private static final String AUDIENCE_TEST = "audience1";
    private static final String ACTION_VERSION_V1 = "v1";

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        CommonTestUtils.initPrivilegedCarbonContext(ORG_NAME, 1, "abc@wso2.com");

        IdentityContext.getThreadLocalIdentityContext().setAccessTokenIssuedOrganization(ORG_NAME);
        preIssueAccessTokenRequestBuilder = new PreIssueAccessTokenRequestBuilder();

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(CLIENT_ID_TEST, TENANT_DOMAIN_TEST))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN_TEST)).thenReturn(TEST_URL);
        doReturn(new String[]{AUDIENCE_TEST}).when(oAuthAppDO).getAudiences();
        doReturn(CLIENT_ID_TEST).when(oAuthAppDO).getOauthConsumerKey();
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getOIDCAudience(CLIENT_ID_TEST, oAuthAppDO)).
                thenReturn(new LinkedList<>(Collections.singleton(AUDIENCE_TEST)));
        oAuth2UtilMockedStatic.when(OAuth2Util::isPairwiseSubEnabledForAccessTokens).thenReturn(false);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        doReturn(USER_ID_TEST).when(authenticatedUser).getAuthenticatedSubjectIdentifier();

        claimHandlerUtilMockedStatic = mockStatic(ClaimHandlerUtil.class);
        CustomClaimsCallbackHandler customClaimsCallbackHandler = mock(CustomClaimsCallbackHandler.class);
        claimHandlerUtilMockedStatic.when(() -> ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO)).
                thenReturn(customClaimsCallbackHandler);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(() -> LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);

        AuthorizationGrantHandler authorizationGrantHandler = mock(AuthorizationGrantHandler.class);
        when(authorizationGrantHandler.isOfTypeApplicationUser(any())).thenReturn(true);
        Map<String, AuthorizationGrantHandler> mockGrantTypesMap = new HashMap<>();
        mockGrantTypesMap.put(GRANT_TYPE_TEST, authorizationGrantHandler);
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
        Assert.assertEquals(actionType, ActionType.PRE_ISSUE_ACCESS_TOKEN);
    }

    @Test
    public void testBuildActionExecutionRequest()
            throws ActionExecutionRequestBuilderException, OrganizationManagementException {

        MinimalOrganization minimalOrganization =
                new MinimalOrganization.Builder().id(ORG_ID).name(ORG_NAME).organizationHandle(ORG_HANDLE)
                        .depth(ORG_DEPTH).build();

        ActionExecutionRequestContext mockContext = mock(ActionExecutionRequestContext.class);
        Action mockAction = mock(Action.class);
        when(mockContext.getAction()).thenReturn(mockAction);
        when(mockAction.getActionVersion()).thenReturn(ACTION_VERSION_V1);

        try (MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolder =
                     mockStatic(OAuthComponentServiceHolder.class)) {

            oAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(mockOAuthComponentServiceHolder);
            when(mockOAuthComponentServiceHolder.getOrganizationManager()).thenReturn(mockOrganizationManager);
            when(mockOrganizationManager.resolveOrganizationId(ORG_NAME)).thenReturn(ORG_ID);
            when(mockOrganizationManager.getMinimalOrganization(anyString(), nullable(String.class)))
                    .thenReturn(minimalOrganization);

            ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder.
                    buildActionExecutionRequest(
                            FlowContext.create().add("tokenMessageContext", getMockTokenMessageContext()), null);
            Assert.assertNotNull(actionExecutionRequest);
            Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ACCESS_TOKEN);
            assertEvent((PreIssueAccessTokenEvent) actionExecutionRequest.getEvent(), getExpectedEvent());
            assertAllowedOperations(actionExecutionRequest.getAllowedOperations(), getExpectedAllowedOperations());
        }
    }

    /**
     * Assert that the actual event matches the expected event.
     *
     * @param actualEvent   The actual PreIssueAccessTokenEvent.
     * @param expectedEvent The expected PreIssueAccessTokenEvent.
     */

    private void assertEvent(PreIssueAccessTokenEvent actualEvent, PreIssueAccessTokenEvent expectedEvent) {

        assertEquals(expectedEvent.getTenant().getId(), actualEvent.getTenant().getId());
        assertOrganization(expectedEvent.getOrganization(), actualEvent.getOrganization());
        assertOrganization(expectedEvent.getUser().getOrganization(), actualEvent.getUser().getOrganization());
        assertAccessToken(actualEvent.getAccessToken(), expectedEvent.getAccessToken());
        assertRequest((TokenRequest) actualEvent.getRequest(), (TokenRequest) expectedEvent.getRequest());
    }

    private void assertOrganization(Organization expectedOrg, Organization actualOrg) {

        assertNotNull(actualOrg);
        assertEquals(actualOrg.getId(), expectedOrg.getId());
        assertEquals(actualOrg.getName(), expectedOrg.getName());
    }

    /**
     * Assert that the actual access token matches the expected access token.
     *
     * @param actualAccessToken   The actual AccessToken.
     * @param expectedAccessToken The expected AccessToken.
     */

    private static void assertAccessToken(AccessToken actualAccessToken, AccessToken expectedAccessToken) {

        Assert.assertEquals(actualAccessToken.getClaims().size(), expectedAccessToken.getClaims().size());
        for (int i = 0; i < expectedAccessToken.getClaims().size(); i++) {
            AccessToken.Claim actualClaim = actualAccessToken.getClaims().get(i);
            AccessToken.Claim expectedClaim = expectedAccessToken.getClaims().get(i);
            Assert.assertEquals(actualClaim.getName(), expectedClaim.getName());
            Assert.assertEquals(actualClaim.getValue(), expectedClaim.getValue());
        }
        Assert.assertEquals(actualAccessToken.getScopes().size(), expectedAccessToken.getScopes().size());
        for (int i = 0; i < expectedAccessToken.getScopes().size(); i++) {
            String actualScope = expectedAccessToken.getScopes().get(i);
            String expectedScope = expectedAccessToken.getScopes().get(i);
            Assert.assertEquals(actualScope, expectedScope);
        }
    }

    /**
     * Assert that the actual token request matches the expected token request.
     *
     * @param actualRequest   The actual TokenRequest.
     * @param expectedRequest The expected TokenRequest.
     */
    private static void assertRequest(TokenRequest actualRequest, TokenRequest expectedRequest) {

        Assert.assertEquals(actualRequest.getClientId(), expectedRequest.getClientId());
        Assert.assertEquals(actualRequest.getGrantType(), expectedRequest.getGrantType());
        Assert.assertEquals(actualRequest.getScopes().size(), expectedRequest.getScopes().size());
        for (int i = 0; i < expectedRequest.getScopes().size(); i++) {
            Assert.assertEquals(actualRequest.getScopes().get(i), expectedRequest.getScopes().get(i));
        }
        Assert.assertEquals(actualRequest.getAdditionalHeaders().size(), expectedRequest.getAdditionalHeaders().size());
        for (int i = 0; i < expectedRequest.getAdditionalHeaders().size(); i++) {
            Header actualAdditionalHeader = actualRequest.getAdditionalHeaders().get(i);
            Header expectedAdditionalHeader = expectedRequest.getAdditionalHeaders().get(i);
            Assert.assertEquals(actualAdditionalHeader.getName(), expectedAdditionalHeader.getName());
            Assert.assertEquals(actualAdditionalHeader.getValue(), expectedAdditionalHeader.getValue());
        }
        Assert.assertEquals(actualRequest.getAdditionalParams().size(), expectedRequest.getAdditionalParams().size());
        for (int i = 0; i < expectedRequest.getAdditionalParams().size(); i++) {
            Param actualAdditionalParam = actualRequest.getAdditionalParams().get(i);
            Param expectedAdditionalParam = expectedRequest.getAdditionalParams().get(i);
            Assert.assertEquals(actualAdditionalParam.getName(), expectedAdditionalParam.getName());
            Assert.assertEquals(actualAdditionalParam.getValue(), expectedAdditionalParam.getValue());
        }
    }

    /**
     * Assert that the actual allowed operations match the expected allowed operations.
     *
     * @param actual   List of actual AllowedOperation.
     * @param expected List of expected AllowedOperation.
     */
    private void assertAllowedOperations(List<AllowedOperation> actual, List<AllowedOperation> expected) {

        Assert.assertEquals(actual.size(), expected.size());
        for (int i = 0; i < expected.size(); i++) {
            AllowedOperation expectedOperation = expected.get(i);
            AllowedOperation actualOperation = actual.get(i);
            Assert.assertEquals(expectedOperation.getOp(), actualOperation.getOp());
            Assert.assertEquals(expectedOperation.getPaths().size(), actualOperation.getPaths().size());
            for (int j = 0; j < expectedOperation.getPaths().size(); j++) {
                Assert.assertEquals(expectedOperation.getPaths().get(j), actualOperation.getPaths().get(j));
            }
        }
    }

    private OAuthTokenReqMessageContext getMockTokenMessageContext() {

        OAuth2AccessTokenReqDTO tokenReqDTO = mockTokenRequestDTO();
        AuthenticatedUser authenticatedUser = mockAuthenticatedUser();
        return mockMessageContext(tokenReqDTO, authenticatedUser);
    }

    /**
     * Mock the OAuth2 access token request DTO.
     *
     * @return OAuth2AccessTokenReqDTO containing mock token request data.
     */
    private OAuth2AccessTokenReqDTO mockTokenRequestDTO() {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(CLIENT_ID_TEST);
        tokenReqDTO.setClientSecret(CLIENT_SECRET_TEST);
        tokenReqDTO.setGrantType(GRANT_TYPE_TEST);
        tokenReqDTO.setTenantDomain(TENANT_DOMAIN_TEST);
        tokenReqDTO.setResourceOwnerUsername(USERNAME_TEST);
        tokenReqDTO.setResourceOwnerPassword(PASSWORD_TEST);
        tokenReqDTO.setScope(new String[]{"scope1", "scope2"});
        HttpRequestHeader[] requestHeaders = new HttpRequestHeader[]{
                new HttpRequestHeader("authorization",
                        getBase64EncodedString(CLIENT_ID_TEST, CLIENT_SECRET_TEST)),
                new HttpRequestHeader("accept", "application/json")
        };
        tokenReqDTO.setHttpRequestHeaders(requestHeaders);
        RequestParameter[] requestParameters = new RequestParameter[]{
                new RequestParameter("grant_type", GRANT_TYPE_TEST),
                new RequestParameter("username", USERNAME_TEST),
                new RequestParameter("password", PASSWORD_TEST),
                new RequestParameter("scope", "scope1", "scope2")
        };
        tokenReqDTO.setRequestParameters(requestParameters);
        return tokenReqDTO;
    }

    /**
     * Mock an authenticated user.
     *
     * @return AuthenticatedUser object containing mock user data.
     */
    private static AuthenticatedUser mockAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setAccessingOrganization(ORG_ID);
        return authenticatedUser;
    }

    /**
     * Mock the OAuthTokenReqMessageContext for testing.
     *
     * @param tokenReqDTO       The OAuth2AccessTokenReqDTO used in the message context.
     * @param authenticatedUser The authenticated user for the request.
     * @return OAuthTokenReqMessageContext with mock data.
     */
    private static OAuthTokenReqMessageContext mockMessageContext(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                                  AuthenticatedUser authenticatedUser) {

        OAuthTokenReqMessageContext tokenMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenMessageContext.setAuthorizedUser(authenticatedUser);
        tokenMessageContext.setScope(new String[]{"scope1", "scope2"});

        tokenMessageContext.setPreIssueAccessTokenActionsExecuted(false);
        tokenMessageContext.setAudiences(Collections.singletonList(AUDIENCE_TEST));

        tokenMessageContext.addProperty("USER_TYPE", "APPLICATION_USER");
        tokenMessageContext.setValidityPeriod(3600000L);
        return tokenMessageContext;
    }

    /**
     * Get the expected PreIssueAccessTokenEvent for testing.
     *
     * @return PreIssueAccessTokenEvent representing the expected event.
     */
    private PreIssueAccessTokenEvent getExpectedEvent() {

        PreIssueAccessTokenEvent.Builder eventBuilder = new PreIssueAccessTokenEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST))
                .organization(new Organization(ORG_ID, ORG_NAME))
                .user(new User.Builder("76345726419")
                        .organization(new Organization(ORG_ID, ORG_NAME))
                        .build());
        AccessToken.Builder accessTokenBuilder = new AccessToken.Builder();
        accessTokenBuilder
                .addClaim(AccessToken.ClaimNames.ISS.getName(), TEST_URL)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), CLIENT_ID_TEST)
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), "APPLICATION_USER")
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), 3600L)
                .addClaim(AccessToken.ClaimNames.AUD.getName(), new LinkedList<>(Collections.singleton(AUDIENCE_TEST)))
                .addClaim(AccessToken.ClaimNames.SUB.getName(), USER_ID_TEST)
                .scopes(Arrays.asList("scope1", "scope2"));
        eventBuilder.accessToken(accessTokenBuilder.build());
        TokenRequest.Builder requestBuilder = new TokenRequest.Builder();
        requestBuilder
                .clientId(CLIENT_ID_TEST)
                .grantType(GRANT_TYPE_TEST)
                .scopes(Arrays.asList("scope1", "scope2"))
                .addAdditionalHeader("authorization",
                        new String[]{getBase64EncodedString(CLIENT_ID_TEST, CLIENT_SECRET_TEST)})
                .addAdditionalHeader("accept", new String[]{"application/json"})
                .addAdditionalParam("grant_type", new String[]{GRANT_TYPE_TEST})
                .addAdditionalParam("username", new String[]{USERNAME_TEST})
                .addAdditionalParam("password", new String[]{PASSWORD_TEST})
                .addAdditionalParam("scope", new String[]{"scope1", "scope2"});
        eventBuilder.request(requestBuilder.build());

        return eventBuilder.build();
    }

    /**
     * Get the expected allowed operations for the action execution request.
     *
     * @return List of AllowedOperation representing the expected operations.
     */
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
                "/accessToken/claims/expires_in"));
        allowedOperations.add(addOperation);
        allowedOperations.add(removeOperation);
        allowedOperations.add(replaceOperation);

        return allowedOperations;
    }

    /**
     * Encode the client ID and client secret as a Base64 encoded string.
     *
     * @param clientId     The client ID.
     * @param clientSecret The client secret.
     * @return Base64 encoded string representing client ID and secret.
     */
    private String getBase64EncodedString(String clientId, String clientSecret) {

        return new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
    }

}
