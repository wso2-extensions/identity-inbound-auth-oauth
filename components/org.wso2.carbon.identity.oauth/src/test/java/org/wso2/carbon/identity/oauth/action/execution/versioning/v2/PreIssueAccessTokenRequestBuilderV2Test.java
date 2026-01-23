/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action.execution.versioning.v2;

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
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.execution.api.model.UserStore;
import org.wso2.carbon.identity.action.management.api.model.Action;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.action.execution.versioning.PreIssueAccessTokenRequestBuilderBaseTestCase;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.RefreshToken;
import org.wso2.carbon.identity.oauth.action.model.TokenRequest;
import org.wso2.carbon.identity.oauth.action.versioning.v2.PreIssueAccessTokenRequestBuilderV2;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit test class for PreIssueAccessTokenRequestBuilderV2.
 */
public class PreIssueAccessTokenRequestBuilderV2Test extends PreIssueAccessTokenRequestBuilderBaseTestCase {

    @Mock
    OrganizationManager mockOrganizationManager;

    @Mock
    OAuthComponentServiceHolder mockOAuthComponentServiceHolder;

    private static final String ORG_NAME = "test.com";
    private static final String ORG_ID = "2364283-349o34nnv-92713972nx";
    private static final String ORG_HANDLE = "testhandle";
    private static final int ORG_DEPTH = 1;
    private PreIssueAccessTokenRequestBuilderV2 preIssueAccessTokenRequestBuilder;

    private MockedStatic<ClaimHandlerUtil> claimHandlerUtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;

    private static final String CLIENT_ID_TEST = "test-client-id";
    private static final String CLIENT_SECRET_TEST = "test-client-secret";
    private static final String GRANT_TYPE_TEST = "password";
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static final String USER_ID_TEST = "76345726419";
    private static final String USERNAME_TEST = "testUser";
    private static final String PASSWORD_TEST = "test@123";
    private static final String USER_STORE_TEST = "PRIMARY";
    private static final String TEST_URL = "https://test.com/oauth2/token";
    private static final String AUDIENCE_TEST = "audience1";
    private static final String FEDERATED_IDP_NAME = "Google";
    private static final String SSO_FEDERATED_IDP = "SSO";
    private static final String ACCESSING_ORG_ID = "accessing-org-123";
    private static final String USER_RESIDENT_ORG_ID = "resident-org-123";
    private static final String ACTOR_SUB = "actor-user-456";
    private static final String ACTION_VERSION_V2 = "v2";

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        CommonTestUtils.initPrivilegedCarbonContext(ORG_NAME, TENANT_ID_TEST, "abc@wso2.com");

        IdentityContext.getThreadLocalIdentityContext().setAccessTokenIssuedOrganization(ORG_NAME);
        preIssueAccessTokenRequestBuilder = new PreIssueAccessTokenRequestBuilderV2();

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);

        oAuth2UtilMockedStatic.when(() ->
                        OAuth2Util.getAppInformationByClientId(CLIENT_ID_TEST, TENANT_DOMAIN_TEST))
                .thenReturn(oAuthAppDO);
        oAuth2UtilMockedStatic.when(() ->
                        OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN_TEST))
                .thenReturn(TEST_URL);
        oAuth2UtilMockedStatic.when(() ->
                        OAuth2Util.getOIDCAudience(CLIENT_ID_TEST, oAuthAppDO))
                .thenReturn(new LinkedList<>(Collections.singletonList(AUDIENCE_TEST)));
        oAuth2UtilMockedStatic.when(OAuth2Util::isPairwiseSubEnabledForAccessTokens).thenReturn(false);

        doReturn(CLIENT_ID_TEST).when(oAuthAppDO).getOauthConsumerKey();
        doReturn("JWT").when(oAuthAppDO).getTokenType();
        doReturn(GRANT_TYPE_TEST + " " + OAuthConstants.GrantTypes.REFRESH_TOKEN)
                .when(oAuthAppDO).getGrantTypes();
        doReturn(3600L).when(oAuthAppDO).getRefreshTokenExpiryTime();

        claimHandlerUtilMockedStatic = mockStatic(ClaimHandlerUtil.class);
        CustomClaimsCallbackHandler customClaimsCallbackHandler = mock(CustomClaimsCallbackHandler.class);
        claimHandlerUtilMockedStatic.when(() ->
                        ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO))
                .thenReturn(customClaimsCallbackHandler);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getLoginTenantId).thenReturn(TENANT_ID_TEST);
        identityTenantUtilMockedStatic.when(() ->
                        IdentityTenantUtil.getTenantDomain(TENANT_ID_TEST)).thenReturn(TENANT_DOMAIN_TEST);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        AuthorizationGrantHandler authorizationGrantHandler = mock(AuthorizationGrantHandler.class);
        when(authorizationGrantHandler.isOfTypeApplicationUser(any())).thenReturn(true);

        Map<String, AuthorizationGrantHandler> mockGrantTypesMap = new HashMap<>();
        mockGrantTypesMap.put(GRANT_TYPE_TEST, authorizationGrantHandler);
        mockGrantTypesMap.put(OAuthConstants.GrantTypes.REFRESH_TOKEN, authorizationGrantHandler);
        mockGrantTypesMap.put(OAuthConstants.GrantTypes.ORGANIZATION_SWITCH, authorizationGrantHandler);

        oAuthServerConfiguration.when(() ->
                        OAuthServerConfiguration.getInstance().getSupportedGrantTypes()).thenReturn(mockGrantTypesMap);
        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);
        oAuthComponentServiceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance)
                .thenReturn(mockOAuthComponentServiceHolder);
        when(mockOAuthComponentServiceHolder.getOrganizationManager()).thenReturn(mockOrganizationManager);
    }

    @AfterClass
    public void tearDown() {

        preIssueAccessTokenRequestBuilder = null;
        oAuth2UtilMockedStatic.close();
        oAuthServerConfiguration.close();
        claimHandlerUtilMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        loggerUtils.close();
        oAuthComponentServiceHolderMockedStatic.close();
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
                new MinimalOrganization.Builder()
                        .id(ORG_ID)
                        .name(ORG_NAME)
                        .organizationHandle(ORG_HANDLE)
                        .depth(ORG_DEPTH)
                        .build();

        ActionExecutionRequestContext mockContext = mock(ActionExecutionRequestContext.class);
        Action mockAction = mock(Action.class);
        when(mockAction.getActionVersion()).thenReturn(ACTION_VERSION_V2);
        when(mockContext.getAction()).thenReturn(mockAction);

        when(mockOrganizationManager.resolveOrganizationId(ORG_NAME)).thenReturn(ORG_ID);
        when(mockOrganizationManager.getMinimalOrganization(anyString(), nullable(String.class)))
                .thenReturn(minimalOrganization);

        ActionExecutionRequest actionExecutionRequest =
                preIssueAccessTokenRequestBuilder.buildActionExecutionRequest(
                        FlowContext.create().add("tokenMessageContext", getMockTokenMessageContext()), mockContext);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ACCESS_TOKEN);
        assertEvent((PreIssueAccessTokenEvent) actionExecutionRequest.getEvent(), getExpectedEvent());
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations(), getExpectedAllowedOperations());
    }

    @Test
    public void buildActionExecutionRequestWithImpersonatingActorClaim() throws ActionExecutionRequestBuilderException {

        OAuthTokenReqMessageContext tokenContext = getMockTokenMessageContext();
        tokenContext.addProperty(OAuthConstants.IMPERSONATING_ACTOR, ACTOR_SUB);

        ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder
                .buildActionExecutionRequest(FlowContext.create()
                        .add("tokenMessageContext", tokenContext), null);

        PreIssueAccessTokenEvent event = (PreIssueAccessTokenEvent) actionExecutionRequest.getEvent();
        AccessToken.Claim actClaim = event.getAccessToken().getClaims().stream()
                .filter(c -> c.getName().equals("act"))
                .findFirst()
                .orElse(null);

        Assert.assertNotNull(actClaim);
        Map<String, Object> actValue = (Map<String, Object>) actClaim.getValue();
        Assert.assertEquals(actValue.get("sub"), ACTOR_SUB);
    }

    @Test
    public void buildActionExecutionRequestWithFederatedUser() throws
            ActionExecutionRequestBuilderException, OrganizationManagementException {

        AuthenticatedUser federatedUser = mockAuthenticatedUser();
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(FEDERATED_IDP_NAME);

        OAuthTokenReqMessageContext tokenContext = getMockTokenMessageContext();
        tokenContext.setAuthorizedUser(federatedUser);

        when(mockOrganizationManager.resolveOrganizationId(TENANT_DOMAIN_TEST)).thenReturn(ORG_ID);
        when(mockOrganizationManager.getMinimalOrganization(eq(ORG_ID), eq(TENANT_DOMAIN_TEST)))
                .thenReturn(new MinimalOrganization.Builder().id(ORG_ID).name(ORG_NAME).build());

        ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder
                .buildActionExecutionRequest(FlowContext.create()
                        .add("tokenMessageContext", tokenContext), null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueAccessTokenEvent event = (PreIssueAccessTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
        Assert.assertEquals(event.getUser().getUserType(), "FEDERATED");
        Assert.assertEquals(event.getUser().getFederatedIdP(), FEDERATED_IDP_NAME);
    }

    @Test
    public void buildActionExecutionRequestWithSSOFederatedUser() throws
            ActionExecutionRequestBuilderException {

        AuthenticatedUser ssoUser = mockAuthenticatedUser();
        ssoUser.setFederatedUser(true);
        ssoUser.setFederatedIdPName(SSO_FEDERATED_IDP);
        ssoUser.setAccessingOrganization(ACCESSING_ORG_ID);
        ssoUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        AuthenticatedUser associatedUser = mockAuthenticatedUser();

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(
                        eq(USER_ID_TEST),
                        eq(TENANT_DOMAIN_TEST),
                        eq(ACCESSING_ORG_ID),
                        eq(USER_RESIDENT_ORG_ID),
                        eq(CLIENT_ID_TEST))).thenReturn(associatedUser);

        OAuthTokenReqMessageContext tokenContext = getMockTokenMessageContext();
        tokenContext.setAuthorizedUser(ssoUser);

        ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder
                .buildActionExecutionRequest(FlowContext.create()
                        .add("tokenMessageContext", tokenContext), null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueAccessTokenEvent event = (PreIssueAccessTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
        Assert.assertEquals(event.getUser().getUserType(), "LOCAL");
    }

    @Test
    public void testAllowedOperationsWithRefreshToken() throws ActionExecutionRequestBuilderException {

        OAuthTokenReqMessageContext tokenContext = getMockTokenMessageContext();

        ActionExecutionRequest actionExecutionRequest = preIssueAccessTokenRequestBuilder
                .buildActionExecutionRequest(FlowContext.create()
                        .add("tokenMessageContext", tokenContext), null);

        List<AllowedOperation> allowedOperations = actionExecutionRequest.getAllowedOperations();
        boolean hasRefreshTokenPath = allowedOperations.stream()
                .filter(op -> op.getOp() == Operation.REPLACE)
                .anyMatch(op -> op.getPaths().contains("/refreshToken/claims/expires_in"));

        Assert.assertTrue(hasRefreshTokenPath);
    }

    private OAuthTokenReqMessageContext getMockTokenMessageContext() {

        OAuth2AccessTokenReqDTO tokenReqDTO = mockTokenRequestDTO();
        AuthenticatedUser authenticatedUser = mockAuthenticatedUser();
        return mockMessageContext(tokenReqDTO, authenticatedUser);
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
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        return authenticatedUser;
    }

    /**
     * Get the expected PreIssueAccessTokenEvent for testing.
     *
     * @return PreIssueAccessTokenEvent representing the expected event.
     */
    private PreIssueAccessTokenEvent getExpectedEvent() {

        PreIssueAccessTokenEvent.Builder eventBuilder = new PreIssueAccessTokenEvent.Builder();
        eventBuilder
                .tenant(new Tenant(String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST))
                .organization(new Organization(ORG_ID, ORG_NAME))
                .user(new User.Builder(USER_ID_TEST)
                        .organization(new Organization(ORG_ID, ORG_NAME))
                        .build())
                .userStore(new UserStore(USER_STORE_TEST));
        AccessToken.Builder accessTokenBuilder = new AccessToken.Builder();
        accessTokenBuilder
                .addClaim(AccessToken.ClaimNames.ISS.getName(), TEST_URL)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), CLIENT_ID_TEST)
                .addClaim(
                        AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), "APPLICATION_USER")
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), 3600L)
                .addClaim(AccessToken.ClaimNames.AUD.getName(), Collections.singletonList(AUDIENCE_TEST))
                .addClaim(AccessToken.ClaimNames.SUB.getName(), USER_ID_TEST)
                .scopes(Arrays.asList("scope1", "scope2"));
        eventBuilder.accessToken(accessTokenBuilder.build());

        RefreshToken.Builder refreshTokenBuilder = new RefreshToken.Builder()
                .addClaim("expires_in", 3600L);
        eventBuilder.refreshToken(refreshTokenBuilder.build());

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
                "/accessToken/claims/expires_in",
                "/refreshToken/claims/expires_in"));
        allowedOperations.add(addOperation);
        allowedOperations.add(removeOperation);
        allowedOperations.add(replaceOperation);

        return allowedOperations;
    }
}
