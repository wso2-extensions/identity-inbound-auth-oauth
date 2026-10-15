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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.Event;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Request;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.execution.api.model.UserStore;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDToken;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDTokenRequest;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.PreIssueIDTokenEvent;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This class is responsible for building the action execution request for the pre issue id token action.
 */
public class PreIssueIDTokenRequestBuilder implements ActionExecutionRequestBuilder {

    private static final Log LOG = LogFactory.getLog(PreIssueIDTokenRequestBuilder.class);
    public static final String CLAIMS_PATH_PREFIX = "/idToken/claims/";
    private static final String TOKEN_REQUEST_MESSAGE_CONTEXT = "tokenReqMessageContext";
    private static final String AUTHZ_REQUEST_MESSAGE_CONTEXT = "authzReqMessageContext";
    private static final String REQUEST_TYPE = "requestType";
    private static final String REQUEST_TYPE_TOKEN = "token";
    private static final String REQUEST_TYPE_AUTHZ = "authz";
    private static final String ID_TOKEN_DTO = "idTokenDTO";
    private static final String FEDERATED_USER = "FEDERATED";
    private static final String LOCAL_USER = "LOCAL";
    private static final String SSO_FEDERATED_IDP = "SSO";

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ID_TOKEN;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                              ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        IDTokenDTO idTokenDTO = flowContext.getValue(ID_TOKEN_DTO, IDTokenDTO.class);
        Map<String, Object> oidcCustomClaims = idTokenDTO.getCustomOIDCClaims() != null ?
                idTokenDTO.getCustomOIDCClaims() : new HashMap<>();

        String requestType = flowContext.getValue(REQUEST_TYPE, String.class);
        switch (requestType) {
            case REQUEST_TYPE_TOKEN:
                return buildActionExecutionRequest(
                        flowContext.getValue(TOKEN_REQUEST_MESSAGE_CONTEXT, OAuthTokenReqMessageContext.class),
                        idTokenDTO, oidcCustomClaims);
            case REQUEST_TYPE_AUTHZ:
                return buildActionExecutionRequest(
                        flowContext.getValue(AUTHZ_REQUEST_MESSAGE_CONTEXT, OAuthAuthzReqMessageContext.class),
                        idTokenDTO, oidcCustomClaims);
            default:
                throw new ActionExecutionRequestBuilderException("Invalid request type found in the flow context: " +
                        requestType);
        }
    }

    private ActionExecutionRequest buildActionExecutionRequest(OAuthTokenReqMessageContext tokenMessageContext,
                                                              IDTokenDTO idTokenDTO,
                                                              Map<String, Object> oidcCustomClaims) {

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(tokenMessageContext, idTokenDTO, oidcCustomClaims));
        actionRequestBuilder.allowedOperations(getAllowedOperations(oidcCustomClaims));
        return actionRequestBuilder.build();
    }

    private ActionExecutionRequest buildActionExecutionRequest(OAuthAuthzReqMessageContext authzMessageContext,
                                                              IDTokenDTO idTokenDTO,
                                                              Map<String, Object> oidcCustomClaims) {

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(authzMessageContext, idTokenDTO, oidcCustomClaims));
        actionRequestBuilder.allowedOperations(getAllowedOperations(oidcCustomClaims));
        return actionRequestBuilder.build();
    }

    private Event getEvent(OAuthTokenReqMessageContext tokenMessageContext,
                           IDTokenDTO idTokenDTO,
                           Map<String, Object> oidcCustomClaims) {

        PreIssueIDTokenEvent.Builder eventBuilder = new PreIssueIDTokenEvent.Builder();
        OAuth2AccessTokenReqDTO tokenReqDTO = tokenMessageContext.getOauth2AccessTokenReqDTO();
        AuthenticatedUser authorizedUser = tokenMessageContext.getAuthorizedUser();

        int loginTenantId = IdentityTenantUtil.getLoginTenantId();
        eventBuilder.tenant(new Tenant(String.valueOf(loginTenantId),
                IdentityTenantUtil.getTenantDomain(loginTenantId)));

        String[] requestScopes = tokenMessageContext.getScope();

        if (authorizedUser != null) {
            setUserForEventBuilder(eventBuilder, authorizedUser, tokenReqDTO.getClientId(),
                    tokenReqDTO.getGrantType());
            if (authorizedUser.getUserStoreDomain() != null) {
                eventBuilder.userStore(new UserStore(authorizedUser.getUserStoreDomain()));
            }
        }

        eventBuilder.organization(buildIDTokenIssuingOrganization());
        eventBuilder.idToken(getIdToken(idTokenDTO, oidcCustomClaims));
        eventBuilder.request(getRequest(tokenReqDTO, requestScopes));
        return eventBuilder.build();
    }

    private Event getEvent(OAuthAuthzReqMessageContext authzMessageContext,
                           IDTokenDTO idTokenDTO,
                           Map<String, Object> oidcCustomClaims) {

        AuthenticatedUser authorizedUser = authzMessageContext.getAuthorizationReqDTO().getUser();

        PreIssueIDTokenEvent.Builder eventBuilder = new PreIssueIDTokenEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(
                authzMessageContext.getAuthorizationReqDTO().getTenantDomain())),
                authzMessageContext.getAuthorizationReqDTO().getTenantDomain()));

        if (authorizedUser != null) {
            setUserForEventBuilder(eventBuilder, authorizedUser,
                    authzMessageContext.getAuthorizationReqDTO().getConsumerKey(), null);
            if (authorizedUser.getUserStoreDomain() != null) {
                eventBuilder.userStore(new UserStore(authorizedUser.getUserStoreDomain()));
            }
        }

        eventBuilder.organization(buildIDTokenIssuingOrganization());
        eventBuilder.idToken(getIdToken(idTokenDTO, oidcCustomClaims));
        eventBuilder.request(getRequest(authzMessageContext.getAuthorizationReqDTO()));
        return eventBuilder.build();
    }

    private List<AllowedOperation> getAllowedOperations(Map<String, Object> claimsToAdd) {

        List<String> removeOrReplacePaths = getRemoveOrReplacePaths(claimsToAdd);

        List<String> replacePaths = new ArrayList<>(removeOrReplacePaths);
        replacePaths.add(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName());

        AllowedOperation addOperation =
                createAllowedOperation(Operation.ADD, Arrays.asList(CLAIMS_PATH_PREFIX,
                        CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/"));
        AllowedOperation removeOperation = createAllowedOperation(Operation.REMOVE, removeOrReplacePaths);
        AllowedOperation replaceOperation = createAllowedOperation(Operation.REPLACE, replacePaths);
        return Arrays.asList(addOperation, removeOperation, replaceOperation);
    }

    private List<String> getRemoveOrReplacePaths(Map<String, Object> oidcClaims) {

        List<String> removeOrReplacePaths = new ArrayList<>();
        for (Map.Entry<String, Object> entry : oidcClaims.entrySet()) {

            String basePath = CLAIMS_PATH_PREFIX + entry.getKey();
            Object value = entry.getValue();

            removeOrReplacePaths.add(basePath);
            if (value instanceof String || value instanceof Number || value instanceof Boolean) {
                continue;
            }
            if (value instanceof List || value instanceof String[]) {
                removeOrReplacePaths.add(basePath + "/");
                continue;
            }

            // Handle nested objects
            if (value instanceof Map) {
                collectNestedClaimPaths(basePath, value, removeOrReplacePaths);
            }
        }
        removeOrReplacePaths.add(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/");
        return removeOrReplacePaths;
    }

    private void collectNestedClaimPaths(String basePath, Object value, List<String> paths) {

        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;

            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String)) {
                    continue;
                }
                String childPath = basePath + "/" + entry.getKey();
                paths.add(childPath);

                collectNestedClaimPaths(childPath, entry.getValue(), paths);
            }
        }
    }

    private AllowedOperation createAllowedOperation(Operation op, List<String> paths) {

        AllowedOperation operation = new AllowedOperation();
        operation.setOp(op);
        operation.setPaths(new ArrayList<>(paths));
        return operation;
    }

    private void setUserForEventBuilder(PreIssueIDTokenEvent.Builder eventBuilder, AuthenticatedUser authenticatedUser,
                                        String clientID, String grantType) {

        try {
            User user;
            if (authenticatedUser.isFederatedUser()) {
                user = resolveFederatedUser(authenticatedUser, grantType, clientID);
            } else {
                user = resolveLocalUser(authenticatedUser, grantType);
            }

            if (user != null) {
                eventBuilder.user(user);
            }
        } catch (UserIdNotFoundException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format(
                        "Error occurred while retrieving user id of the authorized user for application: " + clientID +
                                "for grantType/ResponseType: " + grantType), e);
            }
        }
    }

    private User resolveFederatedUser(AuthenticatedUser authenticatedUser, String grantType, String clientID)
            throws UserIdNotFoundException {

        if (SSO_FEDERATED_IDP.equalsIgnoreCase(authenticatedUser.getFederatedIdPName())) {
            return resolveSSOFederatedUser(authenticatedUser, grantType, clientID);
        }
        return resolveFederatedUser(authenticatedUser, grantType);
    }

    private User resolveFederatedUser(AuthenticatedUser authenticatedUser, String grantType) {

        User.Builder userBuilder = new User.Builder(null);
        userBuilder.userType(FEDERATED_USER);
        userBuilder.federatedIdP(authenticatedUser.getFederatedIdPName());
        userBuilder.organization(resolveUserAuthenticatedOrganization(authenticatedUser));

        if (OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType)) {
            Organization accessingOrg;
            if (authenticatedUser.getAccessingOrganization() != null) {
                accessingOrg = buildOrganization(authenticatedUser.getAccessingOrganization(),
                        authenticatedUser.getTenantDomain());
                // In case of org switch, if accessing org is not set, it means user is switching to root org.
            } else {
                accessingOrg = buildOrganization(
                        resolveOrganizationId(authenticatedUser.getTenantDomain()),
                        authenticatedUser.getTenantDomain());
            }
            userBuilder.accessingOrganization(accessingOrg);
        }
        return userBuilder.build();
    }

    private User resolveLocalUser(AuthenticatedUser authenticatedUser, String grantType)
            throws UserIdNotFoundException {

        User.Builder userBuilder = new User.Builder(authenticatedUser.getUserId());
        userBuilder.userType(LOCAL_USER);
        userBuilder.organization(resolveUserAuthenticatedOrganization(authenticatedUser));

        if (OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType)) {
            Organization accessingOrg;
            if (authenticatedUser.getAccessingOrganization() != null) {
                accessingOrg = buildOrganization(authenticatedUser.getAccessingOrganization(),
                        authenticatedUser.getTenantDomain());
                // In case of org switch, if accessing org is not set, it means user is switching to root org.
            } else {
                accessingOrg = buildOrganization(
                        resolveOrganizationId(authenticatedUser.getTenantDomain()),
                        authenticatedUser.getTenantDomain());
            }
            userBuilder.accessingOrganization(accessingOrg);
        }
        return userBuilder.build();
    }

    private User resolveSSOFederatedUser(AuthenticatedUser authenticatedUser, String grantType, String clientID)
            throws UserIdNotFoundException {

        try {
            AuthenticatedUser associatedUser = OAuth2Util.getAuthenticatedUser(
                    authenticatedUser.getUserId(),
                    authenticatedUser.getTenantDomain(),
                    authenticatedUser.getAccessingOrganization(),
                    authenticatedUser.getUserResidentOrganization(),
                    clientID);
            return resolveLocalUser(associatedUser, grantType);
        } catch (IdentityOAuth2Exception ignored) {
            // This means actual associated user is not found, means federated login at sub org level. hence treat as a
            // normal federated Login.
            return resolveFederatedUser(authenticatedUser, grantType);
        }
    }

    private Organization resolveUserAuthenticatedOrganization(AuthenticatedUser authenticatedUser) {

        String tenantDomain = authenticatedUser.getTenantDomain();
        if (authenticatedUser.getUserResidentOrganization() != null) {
            return buildOrganization(authenticatedUser.getUserResidentOrganization(), tenantDomain);
        }
        return buildOrganization(resolveOrganizationId(tenantDomain), tenantDomain);
    }

    private Request getRequest(OAuth2AccessTokenReqDTO tokenRequestDTO, String[] requestScopes) {

        IDTokenRequest.Builder tokenRequestBuilder = new IDTokenRequest.Builder();
        tokenRequestBuilder.clientId(tokenRequestDTO.getClientId());
        tokenRequestBuilder.grantType(tokenRequestDTO.getGrantType());
        if (tokenRequestDTO.getScope() != null && !ArrayUtils.isEmpty(tokenRequestDTO.getScope())) {
            tokenRequestBuilder.scopes(Arrays.asList(tokenRequestDTO.getScope()));
        } else {
            tokenRequestBuilder.scopes(Arrays.asList(requestScopes));
        }

        HttpRequestHeader[] httpHeaders = tokenRequestDTO.getHttpRequestHeaders();
        if (httpHeaders != null) {
            for (HttpRequestHeader header : httpHeaders) {
                tokenRequestBuilder.addAdditionalHeader(header.getName(), header.getValue());
            }
        }

        RequestParameter[] requestParameters = tokenRequestDTO.getRequestParameters();
        if (requestParameters != null) {
            for (RequestParameter parameter : requestParameters) {
                tokenRequestBuilder.addAdditionalParam(parameter.getKey(), parameter.getValue());
            }
        }
        return tokenRequestBuilder.build();
    }

    private Request getRequest(OAuth2AuthorizeReqDTO authzRequestDTO) {

        IDTokenRequest.Builder tokenRequestBuilder = new IDTokenRequest.Builder();
        tokenRequestBuilder.clientId(authzRequestDTO.getConsumerKey());
        tokenRequestBuilder.responseType(authzRequestDTO.getResponseType());
        tokenRequestBuilder.scopes(Arrays.asList(authzRequestDTO.getScopes()));

        HttpRequestHeader[] httpHeaders = authzRequestDTO.getHttpRequestHeaders();
        if (httpHeaders != null) {
            for (HttpRequestHeader header : httpHeaders) {
                tokenRequestBuilder.addAdditionalHeader(header.getName(), header.getValue());
            }
        }

        // Extract request parameters from HttpServletRequestWrapper
        if (authzRequestDTO.getHttpServletRequestWrapper() != null) {
            HttpServletRequestWrapper request = authzRequestDTO.getHttpServletRequestWrapper();
            if (request.getParameterMap() != null) {
                for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
                    tokenRequestBuilder.addAdditionalParam(entry.getKey(), entry.getValue());
                }
            }
        }
        return tokenRequestBuilder.build();
    }

    private IDToken getIdToken(IDTokenDTO idTokenDTO,
                               Map<String, Object> claimsToAdd) {

        IDToken.Builder idTokenBuilder = new IDToken.Builder();
        Map<String, Object> idTokenClaimsSet = idTokenDTO.getIdTokenClaimsSet().getClaims();
        idTokenClaimsSet.forEach(idTokenBuilder::addClaim);
        claimsToAdd.forEach(idTokenBuilder::addClaim);
        idTokenBuilder.addClaim(IDToken.ClaimNames.AUD.getName(), idTokenDTO.getAudience());
        idTokenBuilder.addClaim(IDToken.ClaimNames.EXPIRES_IN.getName(), idTokenDTO.getExpiresIn() / 1000);
        return idTokenBuilder.build();
    }

    private Organization buildIDTokenIssuingOrganization() {

        // Issuing organization is the tenant domain of the login tenant. In Sub organizations, the parent organization
        // issues the ID token, hence issuing organization is resolved using the login tenant domain.
        String idTokenIssuingOrganization = IdentityTenantUtil.getTenantDomain(
                IdentityTenantUtil.getLoginTenantId());
        if (StringUtils.isEmpty(idTokenIssuingOrganization)) {
            return null;
        }

        String organizationId = resolveOrganizationId(idTokenIssuingOrganization);
        return buildOrganization(organizationId, idTokenIssuingOrganization);
    }

    private Organization buildOrganization(String organizationId, String tenantDomain) {

        if (StringUtils.isEmpty(organizationId)) {
            return null;
        }

        OrganizationManager organizationManager = OAuthComponentServiceHolder.getInstance().getOrganizationManager();
        try {
            MinimalOrganization existingOrganization =
                    organizationManager.getMinimalOrganization(organizationId, tenantDomain);

            return new Organization.Builder()
                    .id(existingOrganization.getId())
                    .name(existingOrganization.getName())
                    .orgHandle(existingOrganization.getOrganizationHandle())
                    .depth(existingOrganization.getDepth())
                    .build();
        } catch (OrganizationManagementException e) {
            LOG.error("Error while retrieving organization with ID: " + organizationId, e);
        }
        return null;
    }

    private String resolveOrganizationId(String tenantDomain) {

        OrganizationManager organizationManager = OAuthComponentServiceHolder.getInstance().getOrganizationManager();

        try {
            return organizationManager.resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            LOG.error("Error while retrieving organization Id with tenant: " + tenantDomain, e);
        }
        return null;
    }
}
