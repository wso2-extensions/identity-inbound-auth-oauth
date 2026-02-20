/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.execution;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDToken;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDTokenRequest;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.PreIssueIDTokenEvent;
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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit test class for PreIssueIDTokenRequestBuilder class.
 */
public class PreIssueIDTokenRequestBuilderTest {

    private PreIssueIDTokenRequestBuilder preIssueIDTokenRequestBuilder;

    private MockedStatic<ClaimHandlerUtil> claimHandlerUtilMockedStatic;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<OAuthComponentServiceHolder> oAuthComponentServiceHolderMockedStatic;

    private static final String CLIENT_ID_TEST = "test-client-id";
    private static final String GRANT_TYPE_TEST = "authorization_code";
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = 1234;
    private static final String USER_ID_TEST = "user-123";
    private static final String USERNAME_TEST = "testUser";
    private static final String USER_STORE_TEST = "PRIMARY";
    private static final String TEST_URL = "https://test.com/oauth2/token";
    private static final String AUDIENCE_TEST = "audience1";
    private static final String REQUEST_TYPE = "requestType";
    private static final String REQUEST_TYPE_TOKEN = "token";
    private static final String REQUEST_TYPE_AUTHZ = "authz";
    private static final String ID_TOKEN_DTO = "idTokenDTO";
    private static final String TOKEN_REQUEST_MESSAGE_CONTEXT = "tokenReqMessageContext";
    private static final String AUTHZ_REQUEST_MESSAGE_CONTEXT = "authzReqMessageContext";
    private static final String ORGANIZATION_ID_TEST = "org-123";
    private static final String ORGANIZATION_NAME_TEST = "Test Organization";
    private static final String ORGANIZATION_HANDLE_TEST = "test-org";
    private static final String FEDERATED_IDP_NAME = "Google";
    private static final String SSO_FEDERATED_IDP = "SSO";
    private static final String ACCESSING_ORG_ID = "accessing-org-123";
    private static final String USER_RESIDENT_ORG_ID = "resident-org-123";
    private static final String RESPONSE_TYPE_CODE = "code";

    @BeforeClass
    public void setUp() throws OrganizationManagementException {

        preIssueIDTokenRequestBuilder = new PreIssueIDTokenRequestBuilder();

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
        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getOIDCAudience(CLIENT_ID_TEST, oAuthAppDO))
                .thenReturn(new LinkedList<>(Collections.singleton(AUDIENCE_TEST)));
        oAuth2UtilMockedStatic.when(OAuth2Util::isPairwiseSubEnabledForAccessTokens).thenReturn(false);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        doReturn(USER_ID_TEST).when(authenticatedUser).getAuthenticatedSubjectIdentifier();

        claimHandlerUtilMockedStatic = mockStatic(ClaimHandlerUtil.class);
        CustomClaimsCallbackHandler customClaimsCallbackHandler = mock(CustomClaimsCallbackHandler.class);
        claimHandlerUtilMockedStatic.when(() -> ClaimHandlerUtil.getClaimsCallbackHandler(oAuthAppDO))
                .thenReturn(customClaimsCallbackHandler);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getLoginTenantId).thenReturn(TENANT_ID_TEST);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID_TEST))
                .thenReturn(TENANT_DOMAIN_TEST);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        AuthorizationGrantHandler authorizationGrantHandler = mock(AuthorizationGrantHandler.class);
        Map<String, AuthorizationGrantHandler> mockGrantTypesMap = new HashMap<>();
        mockGrantTypesMap.put(GRANT_TYPE_TEST, authorizationGrantHandler);
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getSupportedGrantTypes())
                .thenReturn(mockGrantTypesMap);

        MinimalOrganization minimalOrganization = new MinimalOrganization.Builder()
                .id(ORGANIZATION_ID_TEST)
                .name(ORGANIZATION_NAME_TEST)
                .organizationHandle(ORGANIZATION_HANDLE_TEST)
                .depth(1)
                .build();

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.getMinimalOrganization(eq(ORGANIZATION_ID_TEST), eq(TENANT_DOMAIN_TEST)))
                .thenReturn(minimalOrganization);
        when(organizationManager.getMinimalOrganization(eq(ORGANIZATION_ID_TEST), eq(null)))
                .thenReturn(minimalOrganization);
        when(organizationManager.getMinimalOrganization(eq(USER_RESIDENT_ORG_ID), eq(TENANT_DOMAIN_TEST)))
                .thenReturn(minimalOrganization);
        when(organizationManager.getMinimalOrganization(eq(ACCESSING_ORG_ID), eq(TENANT_DOMAIN_TEST)))
                .thenReturn(minimalOrganization);
        when(organizationManager.resolveOrganizationId(eq(TENANT_DOMAIN_TEST))).thenReturn(ORGANIZATION_ID_TEST);

        OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
        when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);

        oAuthComponentServiceHolderMockedStatic = mockStatic(OAuthComponentServiceHolder.class);
        oAuthComponentServiceHolderMockedStatic.when(OAuthComponentServiceHolder::getInstance)
                .thenReturn(oAuthComponentServiceHolder);
    }

    @AfterClass
    public void tearDown() {

        preIssueIDTokenRequestBuilder = null;
        oAuth2UtilMockedStatic.close();
        oAuthServerConfiguration.close();
        claimHandlerUtilMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        loggerUtils.close();
        oAuthComponentServiceHolderMockedStatic.close();
    }

    @Test
    public void testGetSupportedActionType() {

        ActionType actionType = preIssueIDTokenRequestBuilder.getSupportedActionType();
        Assert.assertEquals(actionType, ActionType.PRE_ISSUE_ID_TOKEN);
    }

    @Test
    public void testBuildActionExecutionRequest() throws ActionExecutionRequestBuilderException {

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ID_TOKEN);
        assertEvent((PreIssueIDTokenEvent) actionExecutionRequest.getEvent(), getExpectedEvent());
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations(), getExpectedAllowedOperations());
    }

    @Test
    public void testBuildActionExecutionRequestWithCustomClaims() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("custom_claim1", "value1");
        customClaims.put("custom_claim2", "value2");

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ID_TOKEN);

        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event);
        Assert.assertNotNull(event.getIdToken());

        // Verify custom claims are included in allowed operations
        List<AllowedOperation> allowedOperations = actionExecutionRequest.getAllowedOperations();
        Assert.assertNotNull(allowedOperations);
    }

    @Test
    public void testBuildActionExecutionRequestWithEmptyCustomClaims() throws ActionExecutionRequestBuilderException {

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ID_TOKEN);
    }

    @Test
    public void testBuildActionExecutionRequestWithNullCustomClaims() throws ActionExecutionRequestBuilderException {

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(null);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ID_TOKEN);
    }

    @Test
    public void testCollectNestedClaimPathsWithInvalidKeys() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        Map<Object, Object> invalidKeyMap = new HashMap<>();
        invalidKeyMap.put(123, "value");
        invalidKeyMap.put("valid", "value");
        customClaims.put("parent", invalidKeyMap);

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);
        ActionExecutionRequest request = preIssueIDTokenRequestBuilder.
                buildActionExecutionRequest(flowContext, null);
        List<String> paths = request.getAllowedOperations().get(1).getPaths();

        Assert.assertTrue(paths.contains("/idToken/claims/parent/valid"));
        Assert.assertFalse(paths.contains("/idToken/claims/parent/123"));
    }

    @Test
    public void testBuildActionExecutionRequestWithMultipleScopes() throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setScope(new String[]{"openid", "profile", "email", "address", "phone"});

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setScope(new String[]{"openid", "profile", "email", "address", "phone"});

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();

        Assert.assertNotNull(request.getScopes());
        Assert.assertFalse(request.getScopes().isEmpty());
    }

    @Test
    public void testBuildActionExecutionRequestWithEmptyScopes() throws ActionExecutionRequestBuilderException {

        OAuthTokenReqMessageContext tokenContext = getMockTokenMessageContext();
        tokenContext.setScope(new String[]{});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
    }

    @Test
    public void testBuildActionExecutionRequestWithUserAttributes() throws ActionExecutionRequestBuilderException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);


        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getRequest());
    }

    @DataProvider(name = "grantTypeProvider")
    public Object[][] getGrantTypes() {
        return new Object[][]{
                {"authorization_code"},
                {"refresh_token"},
                {"client_credentials"},
                {"password"},
                {"urn:ietf:params:oauth:grant-type:jwt-bearer"}
        };
    }

    @Test(dataProvider = "grantTypeProvider")
    public void testBuildActionExecutionRequestWithDifferentGrantTypes(String grantType)
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(grantType);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertEquals(request.getGrantType(), grantType);
    }

    @Test
    public void testBuildActionExecutionRequestWithHeaders() throws ActionExecutionRequestBuilderException {

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("Content-Type", "application/json"),
                new HttpRequestHeader("Authorization", "Bearer token"),
                new HttpRequestHeader("X-Custom-Header", "custom-value")
        };

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setHttpRequestHeaders(headers);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
    }

    @Test
    public void testBuildActionExecutionRequestWithParameters() throws ActionExecutionRequestBuilderException {

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter("param1", "value1"),
                new RequestParameter("param2", "value2"),
                new RequestParameter("param3", "value3")
        };

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setRequestParameters(parameters);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
    }

    @Test(expectedExceptions = ActionExecutionRequestBuilderException.class)
    public void testBuildActionExecutionRequestWithInvalidRequestType() throws ActionExecutionRequestBuilderException {

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, "invalid_type");

        preIssueIDTokenRequestBuilder.buildActionExecutionRequest(flowContext, null);
    }

    @Test
    public void testBuildActionExecutionRequestWithComplexClaims() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("string_claim", "string_value");
        customClaims.put("number_claim", 12345);
        customClaims.put("boolean_claim", true);
        customClaims.put("array_claim", Arrays.asList("value1", "value2", "value3"));

        Map<String, Object> nestedClaim = new HashMap<>();
        nestedClaim.put("nested_key1", "nested_value1");
        nestedClaim.put("nested_key2", "nested_value2");
        customClaims.put("object_claim", nestedClaim);

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertNotNull(actionExecutionRequest.getAllowedOperations());
    }

    @Test
    public void buildActionExecutionRequestForAuthorizationFlow() throws ActionExecutionRequestBuilderException {

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, getMockAuthzMessageContext())
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.PRE_ISSUE_ID_TOKEN);

        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event);
        Assert.assertNotNull(event.getTenant());
        Assert.assertNotNull(event.getIdToken());
        Assert.assertNotNull(event.getRequest());

        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertEquals(request.getClientId(), CLIENT_ID_TEST);
        Assert.assertEquals(request.getResponseType(), RESPONSE_TYPE_CODE);
        Assert.assertNotNull(request.getScopes());
    }

    @Test
    public void buildActionExecutionRequestWithFederatedUser() throws ActionExecutionRequestBuilderException {

        AuthenticatedUser federatedUser = new AuthenticatedUser();
        federatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        federatedUser.setUserName(USERNAME_TEST);
        federatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(FEDERATED_IDP_NAME);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(federatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
    }

    @Test
    public void buildActionExecutionRequestWithSSOFederatedUser()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser ssoFederatedUser = new AuthenticatedUser();
        ssoFederatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        ssoFederatedUser.setUserName(USERNAME_TEST);
        ssoFederatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        ssoFederatedUser.setUserId(USER_ID_TEST);
        ssoFederatedUser.setFederatedUser(true);
        ssoFederatedUser.setFederatedIdPName(SSO_FEDERATED_IDP);
        ssoFederatedUser.setAccessingOrganization(ACCESSING_ORG_ID);
        ssoFederatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        AuthenticatedUser associatedUser = new AuthenticatedUser();
        associatedUser.setUserId(USER_ID_TEST);
        associatedUser.setUserName(USERNAME_TEST);
        associatedUser.setTenantDomain(TENANT_DOMAIN_TEST);

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(
                eq(USER_ID_TEST),
                eq(TENANT_DOMAIN_TEST),
                eq(ACCESSING_ORG_ID),
                eq(USER_RESIDENT_ORG_ID),
                eq(CLIENT_ID_TEST)))
                .thenReturn(associatedUser);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(ssoFederatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
    }

    @Test
    public void buildActionExecutionRequestWithSSOFederatedUserNotFoundAssociatedUser()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser ssoFederatedUser = new AuthenticatedUser();
        ssoFederatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        ssoFederatedUser.setUserName(USERNAME_TEST);
        ssoFederatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        ssoFederatedUser.setUserId(USER_ID_TEST);
        ssoFederatedUser.setFederatedUser(true);
        ssoFederatedUser.setFederatedIdPName(SSO_FEDERATED_IDP);
        ssoFederatedUser.setAccessingOrganization(ACCESSING_ORG_ID);
        ssoFederatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAuthenticatedUser(
                eq(USER_ID_TEST),
                eq(TENANT_DOMAIN_TEST),
                eq(ACCESSING_ORG_ID),
                eq(USER_RESIDENT_ORG_ID),
                eq(CLIENT_ID_TEST)))
                .thenThrow(new IdentityOAuth2Exception("User not found"));

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(ssoFederatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
    }

    @Test
    public void buildActionExecutionRequestWithOrganizationSwitchGrant()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);
        authenticatedUser.setAccessingOrganization(ACCESSING_ORG_ID);
        authenticatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
    }

    @Test
    public void buildActionExecutionRequestWithOrganizationSwitchGrantForFederatedUser()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser federatedUser = new AuthenticatedUser();
        federatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        federatedUser.setUserName(USERNAME_TEST);
        federatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(FEDERATED_IDP_NAME);
        federatedUser.setAccessingOrganization(ACCESSING_ORG_ID);
        federatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(federatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
    }

    @Test
    public void buildActionExecutionRequestWithoutAccessingOrganizationForOrgSwitch()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser federatedUser = new AuthenticatedUser();
        federatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        federatedUser.setUserName(USERNAME_TEST);
        federatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(FEDERATED_IDP_NAME);
        federatedUser.setAccessingOrganization(null);
        federatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setGrantType(OAuthConstants.GrantTypes.ORGANIZATION_SWITCH);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(federatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
        Assert.assertNotNull(event.getUser().getAccessingOrganization());
    }

    @Test
    public void buildActionExecutionRequestWithNullAuthorizedUser()
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(null);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNull(event.getUser());
        Assert.assertNull(event.getUserStore());
    }

    @Test
    public void buildActionExecutionRequestWithNullUserStoreForLocalUser()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);
        authenticatedUser.setUserStoreDomain(null);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
        Assert.assertNull(event.getUserStore());
    }

    @Test
    public void buildActionExecutionRequestWithOrganizationInformation()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);
        authenticatedUser.setUserResidentOrganization(USER_RESIDENT_ORG_ID);

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getOrganization());
    }

    @Test
    public void buildActionExecutionRequestForAuthzFlowWithFederatedUser()
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser federatedUser = new AuthenticatedUser();
        federatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        federatedUser.setUserName(USERNAME_TEST);
        federatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        federatedUser.setFederatedUser(true);
        federatedUser.setFederatedIdPName(FEDERATED_IDP_NAME);
        federatedUser.setUserStoreDomain(USER_STORE_TEST);

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();
        authzReqDTO.setUser(federatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        Assert.assertNotNull(event.getUser());
        Assert.assertNotNull(event.getUserStore());
    }

    @Test
    public void allowedOperationsHandleComplexClaimStructures() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        Map<String, Object> nestedObject = new HashMap<>();
        nestedObject.put("nested1", "value1");
        customClaims.put("object_claim", nestedObject);

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        List<AllowedOperation> allowedOperations = actionExecutionRequest.getAllowedOperations();
        Assert.assertNotNull(allowedOperations);
        Assert.assertEquals(allowedOperations.size(), 3);
    }

    @Test
    public void buildActionExecutionRequestIncludesAudienceInAllowedOperations()
            throws ActionExecutionRequestBuilderException {

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        List<AllowedOperation> allowedOperations = actionExecutionRequest.getAllowedOperations();

        boolean hasAudInAdd = allowedOperations.stream()
                .filter(op -> op.getOp() == Operation.ADD)
                .anyMatch(op -> op.getPaths().contains("/idToken/claims/aud/"));
        Assert.assertTrue(hasAudInAdd);

        boolean hasAudInRemove = allowedOperations.stream()
                .filter(op -> op.getOp() == Operation.REMOVE)
                .anyMatch(op -> op.getPaths().contains("/idToken/claims/aud/"));
        Assert.assertTrue(hasAudInRemove);

        boolean hasAudInReplace = allowedOperations.stream()
                .filter(op -> op.getOp() == Operation.REPLACE)
                .anyMatch(op -> op.getPaths().contains("/idToken/claims/aud/"));
        Assert.assertTrue(hasAudInReplace);
    }

    @Test
    public void buildActionExecutionRequestUsesRequestScopeWhenTokenReqScopeIsNull()
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setScope(null);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setScope(new String[]{"openid", "profile"});

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getScopes());
        Assert.assertEquals(request.getScopes().size(), 2);
    }

    @Test
    public void idTokenIncludesExpiresInAsClaim() throws ActionExecutionRequestBuilderException {

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setExpiresIn(7200000L);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDToken idToken = event.getIdToken();

        IDToken.Claim expiresInClaim = idToken.getClaims().stream()
                .filter(claim -> claim.getName().equals("expires_in"))
                .findFirst()
                .orElse(null);

        Assert.assertNotNull(expiresInClaim);
        Assert.assertEquals(expiresInClaim.getValue(), 7200L);
    }

    private OAuthAuthzReqMessageContext getMockAuthzMessageContext() {

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        return new OAuthAuthzReqMessageContext(authzReqDTO);
    }

    private OAuth2AuthorizeReqDTO getMockOAuth2AuthorizeReqDTO() {

        OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
        authzReqDTO.setConsumerKey(CLIENT_ID_TEST);
        authzReqDTO.setResponseType(RESPONSE_TYPE_CODE);
        authzReqDTO.setTenantDomain(TENANT_DOMAIN_TEST);
        authzReqDTO.setScopes(new String[]{"openid", "profile"});

        return authzReqDTO;
    }

    /**
     * Assert that the actual event matches the expected event.
     *
     * @param actualEvent   The actual PreIssueIdTokenEvent.
     * @param expectedEvent The expected PreIssueIdTokenEvent.
     */
    private void assertEvent(PreIssueIDTokenEvent actualEvent, PreIssueIDTokenEvent expectedEvent) {

        Assert.assertEquals(actualEvent.getTenant().getId(), expectedEvent.getTenant().getId());
        assertIDToken(actualEvent.getIdToken(), expectedEvent.getIdToken());
        assertRequest((IDTokenRequest) actualEvent.getRequest(), (IDTokenRequest) expectedEvent.getRequest());
    }

    /**
     * Assert that the actual ID token matches the expected ID token.
     *
     * @param actualIDToken   The actual IDToken.
     * @param expectedIDToken The expected IDToken.
     */
    private static void assertIDToken(IDToken actualIDToken, IDToken expectedIDToken) {

        Assert.assertEquals(actualIDToken.getClaims().size(), expectedIDToken.getClaims().size());

        // Create a map of expected claims for key-based comparison
        Map<String, Object> expectedClaimsMap = new HashMap<>();
        for (IDToken.Claim claim : expectedIDToken.getClaims()) {
            expectedClaimsMap.put(claim.getName(), claim.getValue());
        }

        // Compare actual claims against expected claims by key
        for (IDToken.Claim actualClaim : actualIDToken.getClaims()) {
            String claimName = actualClaim.getName();
            Assert.assertTrue(expectedClaimsMap.containsKey(claimName),
                    "Unexpected claim: " + claimName);
            Assert.assertEquals(actualClaim.getValue(), expectedClaimsMap.get(claimName),
                    "Value mismatch for claim: " + claimName);
        }
    }

    /**
     * Assert that the actual token request matches the expected token request.
     *
     * @param actualRequest   The actual IDTokenRequest.
     * @param expectedRequest The expected IDTokenRequest.
     */
    private void assertRequest(IDTokenRequest actualRequest, IDTokenRequest expectedRequest) {

        Assert.assertEquals(actualRequest.getGrantType(), expectedRequest.getGrantType());
        Assert.assertEquals(actualRequest.getScopes().size(), expectedRequest.getScopes().size());
    }

    /**
     * Assert that the actual allowed operations match the expected allowed operations.
     *
     * @param actualOperations   The actual list of AllowedOperation.
     * @param expectedOperations The expected list of AllowedOperation.
     */
    private void assertAllowedOperations(List<AllowedOperation> actualOperations,
                                         List<AllowedOperation> expectedOperations) {

        Assert.assertEquals(actualOperations.size(), expectedOperations.size());
        for (int i = 0; i < expectedOperations.size(); i++) {
            AllowedOperation actualOperation = actualOperations.get(i);
            AllowedOperation expectedOperation = expectedOperations.get(i);
            Assert.assertEquals(actualOperation.getOp(), expectedOperation.getOp());
            Assert.assertEquals(actualOperation.getPaths().size(), expectedOperation.getPaths().size());
        }
    }

    /**
     * Get the expected PreIssueIdTokenEvent for comparison.
     *
     * @return The expected PreIssueIdTokenEvent.
     */
    private PreIssueIDTokenEvent getExpectedEvent() {

        PreIssueIDTokenEvent.Builder eventBuilder = new PreIssueIDTokenEvent.Builder();
        eventBuilder.tenant(new org.wso2.carbon.identity.action.execution.api.model.Tenant(
                String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST));

        IDToken.Builder idTokenBuilder = new IDToken.Builder();
        idTokenBuilder
                .addClaim(IDToken.ClaimNames.SUB.getName(), USER_ID_TEST)
                .addClaim(IDToken.ClaimNames.AUD.getName(), new LinkedList<>(Collections.singleton(AUDIENCE_TEST)))
                .addClaim(IDToken.ClaimNames.ISS.getName(), TEST_URL)
                .addClaim(IDToken.ClaimNames.EXPIRES_IN.getName(), 3600L);
        eventBuilder.idToken(idTokenBuilder.build());

        IDTokenRequest.Builder requestBuilder = new IDTokenRequest.Builder();
        requestBuilder
                .clientId(CLIENT_ID_TEST)
                .grantType(GRANT_TYPE_TEST)
                .scopes(Collections.singletonList("openid"));
        eventBuilder.request(requestBuilder.build());

        return eventBuilder.build();
    }


    /**
     * Get the expected list of AllowedOperation.
     *
     * @return The expected list of AllowedOperation.
     */
    private List<AllowedOperation> getExpectedAllowedOperations() {

        List<AllowedOperation> allowedOperations = new ArrayList<>();

        AllowedOperation addOperation = new AllowedOperation();
        addOperation.setOp(Operation.ADD);
        addOperation.setPaths(Arrays.asList(
                "/idToken/claims/",
                "/idToken/claims/aud/"));

        AllowedOperation removeOperation = new AllowedOperation();
        removeOperation.setOp(Operation.REMOVE);
        removeOperation.setPaths(Collections.singletonList("/idToken/claims/aud/"));

        AllowedOperation replaceOperation = new AllowedOperation();
        replaceOperation.setOp(Operation.REPLACE);
        replaceOperation.setPaths(Arrays.asList(
                "/idToken/claims/aud/",
                "/idToken/claims/expires_in/"));

        allowedOperations.add(addOperation);
        allowedOperations.add(removeOperation);
        allowedOperations.add(replaceOperation);

        return allowedOperations;
    }

    /**
     * Get a mock OAuthTokenReqMessageContext for testing.
     *
     * @return A mock OAuthTokenReqMessageContext.
     */
    private OAuthTokenReqMessageContext getMockTokenMessageContext() {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        return tokenContext;
    }

    /**
     * Get a mock OAuth2AccessTokenReqDTO for testing.
     *
     * @return A mock OAuth2AccessTokenReqDTO.
     */
    private OAuth2AccessTokenReqDTO getMockOAuth2AccessTokenReqDTO() {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(CLIENT_ID_TEST);
        tokenReqDTO.setGrantType(GRANT_TYPE_TEST);
        tokenReqDTO.setTenantDomain(TENANT_DOMAIN_TEST);
        tokenReqDTO.setScope(new String[]{"openid"});

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("Content-Type", "application/json"),
                new HttpRequestHeader("Authorization", "Bearer token")
        };
        tokenReqDTO.setHttpRequestHeaders(headers);

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter("grant_type", GRANT_TYPE_TEST),
                new RequestParameter("client_id", CLIENT_ID_TEST)
        };
        tokenReqDTO.setRequestParameters(parameters);

        return tokenReqDTO;
    }

    /**
     * Get a mock IDTokenDTO for testing.
     *
     * @return A mock IDTokenDTO.
     */
    private IDTokenDTO getMockIDTokenDTO() {

        IDTokenDTO idTokenDTO = new IDTokenDTO();

        // Create JWTClaimsSet for the ID token
        com.nimbusds.jwt.JWTClaimsSet.Builder claimsSetBuilder = new com.nimbusds.jwt.JWTClaimsSet.Builder();
        claimsSetBuilder.claim(IDToken.ClaimNames.SUB.getName(), USER_ID_TEST);
        claimsSetBuilder.claim(IDToken.ClaimNames.ISS.getName(), TEST_URL);

        idTokenDTO.setIdTokenClaimsSet(claimsSetBuilder.build());
        idTokenDTO.setAudience(Collections.singletonList(AUDIENCE_TEST));
        idTokenDTO.setExpiresIn(3600000L);

        return idTokenDTO;
    }

    private void assertComplexPaths(List<String> paths) {

        Assert.assertTrue(paths.contains("/idToken/claims/simple"));
        Assert.assertTrue(paths.contains("/idToken/claims/nested"));
        Assert.assertTrue(paths.contains("/idToken/claims/nested/intermediate"));
        Assert.assertTrue(paths.contains("/idToken/claims/nested/intermediate/leaf"));

        Assert.assertTrue(paths.contains("/idToken/claims/list_claim"));
        Assert.assertTrue(paths.contains("/idToken/claims/list_claim/"));

        Assert.assertTrue(paths.contains("/idToken/claims/aud/"));
    }

    @Test
    public void buildActionExecutionRequestWithMultipleHeadersForTokenFlow()
            throws ActionExecutionRequestBuilderException {

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("Content-Type", "application/x-www-form-urlencoded"),
                new HttpRequestHeader("Authorization", "Bearer token123"),
                new HttpRequestHeader("X-Custom-Header", "custom-value"),
                new HttpRequestHeader("X-Correlation-Id", "correlation-123")
        };

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setHttpRequestHeaders(headers);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertEquals(request.getAdditionalHeaders().size(), 4);
    }

    @Test
    public void buildActionExecutionRequestWithNullHeadersForTokenFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setHttpRequestHeaders(null);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertTrue(request.getAdditionalHeaders().isEmpty());
    }

    @Test
    public void buildActionExecutionRequestWithMultipleParametersForTokenFlow()
            throws ActionExecutionRequestBuilderException {

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter("param1", new String[]{"value1"}),
                new RequestParameter("param2", new String[]{"value2"}),
                new RequestParameter("param3", new String[]{"value3a", "value3b"}),
                new RequestParameter("redirect_uri", new String[]{"https://example.com/callback"})
        };

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setRequestParameters(parameters);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertEquals(request.getAdditionalParams().size(), 4);
    }

    @Test
    public void buildActionExecutionRequestWithNullParametersForTokenFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setRequestParameters(null);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertTrue(request.getAdditionalParams().isEmpty());
    }

    @Test
    public void buildActionExecutionRequestWithHeadersForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("User-Agent", "Mozilla/5.0"),
                new HttpRequestHeader("Accept", "text/html"),
                new HttpRequestHeader("X-Forwarded-For", "192.168.1.1")
        };

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();
        authzReqDTO.setHttpRequestHeaders(headers);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertEquals(request.getAdditionalHeaders().size(), 3);
    }

    @Test
    public void buildActionExecutionRequestWithNullHeadersForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();
        authzReqDTO.setHttpRequestHeaders(null);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertTrue(request.getAdditionalHeaders().isEmpty());
    }

    @Test
    public void buildActionExecutionRequestWithParametersFromHttpServletRequestForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();

        javax.servlet.http.HttpServletRequestWrapper mockRequest =
                mock(javax.servlet.http.HttpServletRequestWrapper.class);

        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("state", new String[]{"state123"});
        parameterMap.put("nonce", new String[]{"nonce456"});
        parameterMap.put("redirect_uri", new String[]{"https://example.com/callback"});
        parameterMap.put("code_challenge", new String[]{"challenge789"});

        when(mockRequest.getParameterMap()).thenReturn(parameterMap);

        authzReqDTO.setHttpServletRequestWrapper(mockRequest);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertEquals(request.getAdditionalParams().size(), 4);
    }

    @Test
    public void buildActionExecutionRequestWithNullHttpServletRequestForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();
        authzReqDTO.setHttpServletRequestWrapper(null);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertTrue(request.getAdditionalParams().isEmpty());
    }

    @Test
    public void buildActionExecutionRequestWithEmptyParameterMapForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();

        javax.servlet.http.HttpServletRequestWrapper mockRequest =
                mock(javax.servlet.http.HttpServletRequestWrapper.class);

        when(mockRequest.getParameterMap()).thenReturn(new HashMap<>());

        authzReqDTO.setHttpServletRequestWrapper(mockRequest);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertTrue(request.getAdditionalParams().isEmpty());
    }

    @Test
    public void buildActionExecutionRequestWithHeadersAndParametersForTokenFlow()
            throws ActionExecutionRequestBuilderException {

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("Content-Type", "application/x-www-form-urlencoded"),
                new HttpRequestHeader("Authorization", "Bearer token123")
        };

        RequestParameter[] parameters = new RequestParameter[]{
                new RequestParameter("grant_type", new String[]{GRANT_TYPE_TEST}),
                new RequestParameter("code", new String[]{"auth_code_123"})
        };

        OAuth2AccessTokenReqDTO tokenReqDTO = getMockOAuth2AccessTokenReqDTO();
        tokenReqDTO.setHttpRequestHeaders(headers);
        tokenReqDTO.setRequestParameters(parameters);

        OAuthTokenReqMessageContext tokenContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        tokenContext.setAuthorizedUser(authenticatedUser);
        tokenContext.setScope(new String[]{"openid"});

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, tokenContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertEquals(request.getAdditionalHeaders().size(), 2);
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertEquals(request.getAdditionalParams().size(), 2);
    }

    @Test
    public void buildActionExecutionRequestWithHeadersAndParametersForAuthzFlow()
            throws ActionExecutionRequestBuilderException {

        HttpRequestHeader[] headers = new HttpRequestHeader[]{
                new HttpRequestHeader("User-Agent", "Mozilla/5.0"),
                new HttpRequestHeader("Accept", "text/html")
        };

        OAuth2AuthorizeReqDTO authzReqDTO = getMockOAuth2AuthorizeReqDTO();
        authzReqDTO.setHttpRequestHeaders(headers);

        javax.servlet.http.HttpServletRequestWrapper mockRequest =
                mock(javax.servlet.http.HttpServletRequestWrapper.class);

        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("state", new String[]{"state123"});
        parameterMap.put("nonce", new String[]{"nonce456"});

        when(mockRequest.getParameterMap()).thenReturn(parameterMap);

        authzReqDTO.setHttpServletRequestWrapper(mockRequest);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_ID_TEST);
        authenticatedUser.setUserName(USERNAME_TEST);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_TEST);
        authenticatedUser.setUserStoreDomain(USER_STORE_TEST);
        authenticatedUser.setUserId(USER_ID_TEST);

        authzReqDTO.setUser(authenticatedUser);

        OAuthAuthzReqMessageContext authzContext = new OAuthAuthzReqMessageContext(authzReqDTO);

        FlowContext flowContext = FlowContext.create()
                .add(AUTHZ_REQUEST_MESSAGE_CONTEXT, authzContext)
                .add(ID_TOKEN_DTO, getMockIDTokenDTO())
                .add(REQUEST_TYPE, REQUEST_TYPE_AUTHZ);

        ActionExecutionRequest actionExecutionRequest = preIssueIDTokenRequestBuilder
                .buildActionExecutionRequest(flowContext, null);

        Assert.assertNotNull(actionExecutionRequest);
        PreIssueIDTokenEvent event = (PreIssueIDTokenEvent) actionExecutionRequest.getEvent();
        IDTokenRequest request = (IDTokenRequest) event.getRequest();
        Assert.assertNotNull(request.getAdditionalHeaders());
        Assert.assertEquals(request.getAdditionalHeaders().size(), 2);
        Assert.assertNotNull(request.getAdditionalParams());
        Assert.assertEquals(request.getAdditionalParams().size(), 2);
    }

    @Test
    public void testGetRemoveOrReplacePathsWithDeeplyNestedClaims() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("simple", "value");
        Map<String, Object> level1 = new HashMap<>();
        Map<String, Object> level2 = new HashMap<>();
        level2.put("leaf", "value");
        level1.put("intermediate", level2);
        customClaims.put("nested", level1);
        customClaims.put("list_claim", Arrays.asList("a", "b"));

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);
        ActionExecutionRequest request = preIssueIDTokenRequestBuilder.buildActionExecutionRequest(
                flowContext, null);

        List<String> removePaths = request.getAllowedOperations().stream()
                .filter(op -> op.getOp() == Operation.REMOVE)
                .findFirst()
                .orElseThrow(() -> new AssertionError("REMOVE operation not found"))
                .getPaths();
        assertComplexPaths(removePaths);

        List<String> replacePaths = request.getAllowedOperations().stream()
                .filter(op -> op.getOp() == Operation.REPLACE)
                .findFirst()
                .orElseThrow(() -> new AssertionError("REPLACE operation not found"))
                .getPaths();
        assertComplexPaths(replacePaths);
    }

    @Test
    public void testGetRemoveAndReplacePathsWithArrays() throws ActionExecutionRequestBuilderException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("array_claim", new String[]{"val1", "val2"});

        IDTokenDTO idTokenDTO = getMockIDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(customClaims);

        FlowContext flowContext = FlowContext.create()
                .add(TOKEN_REQUEST_MESSAGE_CONTEXT, getMockTokenMessageContext())
                .add(ID_TOKEN_DTO, idTokenDTO)
                .add(REQUEST_TYPE, REQUEST_TYPE_TOKEN);

        ActionExecutionRequest request = preIssueIDTokenRequestBuilder.buildActionExecutionRequest(
                flowContext, null);
        List<String> removePaths = request.getAllowedOperations().get(1).getPaths();
        List<String> replacePaths = request.getAllowedOperations().get(2).getPaths();

        Assert.assertTrue(removePaths.contains("/idToken/claims/array_claim"));
        Assert.assertTrue(removePaths.contains("/idToken/claims/array_claim/"));

        Assert.assertTrue(replacePaths.contains("/idToken/claims/array_claim"));
        Assert.assertTrue(replacePaths.contains("/idToken/claims/array_claim/"));
    }
}
