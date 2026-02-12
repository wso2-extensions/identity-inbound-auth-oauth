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

package org.wso2.carbon.identity.oauth.action.versioning.v2;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
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
import org.wso2.carbon.identity.oauth.action.model.AbstractToken;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.RefreshToken;
import org.wso2.carbon.identity.oauth.action.model.TokenRequest;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.openidconnect.util.ClaimHandlerUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * This class is responsible for building the action execution request for the pre issue access token action.
 */
public class PreIssueAccessTokenRequestBuilderV2 implements ActionExecutionRequestBuilder {

    public static final String ACCESS_TOKEN_CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    public static final String REFRESH_TOKEN_CLAIMS_PATH_PREFIX = "/refreshToken/claims/";
    public static final String SCOPES_PATH_PREFIX = "/accessToken/scopes/";
    private static final Log LOG =
            LogFactory.getLog(org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder.class);

    private static final String FEDERATED_USER = "FEDERATED";
    private static final String LOCAL_USER = "LOCAL";
    private static final String SSO_FEDERATED_IDP = "SSO";

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                              ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        OAuthTokenReqMessageContext tokenMessageContext =
                flowContext.getValue("tokenMessageContext", OAuthTokenReqMessageContext.class);

        Map<String, Object> additionalClaimsToAddToToken = getAdditionalClaimsToAddToToken(tokenMessageContext);

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.actionType(getSupportedActionType());

        PreIssueAccessTokenEvent event = getEvent(tokenMessageContext, additionalClaimsToAddToToken);
        actionRequestBuilder.event(event);
        actionRequestBuilder.allowedOperations(
                getAllowedOperations(additionalClaimsToAddToToken, event.getRefreshToken() != null));

        return actionRequestBuilder.build();
    }

    private PreIssueAccessTokenEvent getEvent(OAuthTokenReqMessageContext tokenMessageContext,
                                              Map<String, Object> claimsToAdd)
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokenMessageContext.getOauth2AccessTokenReqDTO();
        AuthenticatedUser authorizedUser = tokenMessageContext.getAuthorizedUser();

        PreIssueAccessTokenEvent.Builder eventBuilder = new PreIssueAccessTokenEvent.Builder();

        int loginTenantId = IdentityTenantUtil.getLoginTenantId();
        eventBuilder.tenant(new Tenant(String.valueOf(loginTenantId),
                IdentityTenantUtil.getTenantDomain(loginTenantId)));

        String[] requestScopes = tokenMessageContext.getScope();
        boolean isAuthorizedForUser = isAccessTokenAuthorizedForUser(tokenReqDTO.getGrantType(), tokenMessageContext);
        if (isAuthorizedForUser && authorizedUser != null) {
            setUserForEventBuilder(eventBuilder, authorizedUser, tokenReqDTO.getClientId(), tokenReqDTO.getGrantType());
            if (StringUtils.isNotEmpty(authorizedUser.getUserStoreDomain())) {
                eventBuilder.userStore(new UserStore(authorizedUser.getUserStoreDomain()));
            }
        }
        eventBuilder.organization(buildAccessTokenIssuedOrganization());

        OAuthAppDO oAuthAppDO = getAppInformation(tokenMessageContext);

        eventBuilder.accessToken(getAccessToken(tokenMessageContext, oAuthAppDO, claimsToAdd));

        if (isRefreshTokenAllowed(oAuthAppDO)) {
            eventBuilder.refreshToken(getRefreshToken(oAuthAppDO, tokenMessageContext));
        }
        eventBuilder.request(getRequest(tokenReqDTO, requestScopes));

        return eventBuilder.build();
    }

    private boolean isRefreshTokenAllowed(OAuthAppDO oAuthAppDO) {

        if (OAuthServerConfiguration.getInstance().getSupportedGrantTypes().containsKey(
                GrantType.REFRESH_TOKEN.toString()) && oAuthAppDO != null) {

            String grantTypes = oAuthAppDO.getGrantTypes();
            if (StringUtils.isNotEmpty(grantTypes)) {
                List<String> supportedGrantTypes = Arrays.asList(grantTypes.split(" "));
                return supportedGrantTypes.contains(OAuthConstants.GrantTypes.REFRESH_TOKEN);
            }
        }
        return false;
    }

    private RefreshToken getRefreshToken(OAuthAppDO oAuthAppDO, OAuthTokenReqMessageContext tokenMessageContext) {

        long refreshTokenValidityPeriod = resolveRefreshTokenValidityPeriod(oAuthAppDO, tokenMessageContext);
        long refreshTokenIssuedAt = resolveRefreshTokenIssuedAt(tokenMessageContext);

        RefreshToken.Builder refreshTokenBuilder = new RefreshToken.Builder()
                .addClaim(RefreshToken.ClaimNames.EXPIRES_IN.getName(), refreshTokenValidityPeriod);

        if (refreshTokenIssuedAt > -1) {
            refreshTokenBuilder.addClaim(AbstractToken.ClaimNames.IAT.getName(), refreshTokenIssuedAt);
        }

        return refreshTokenBuilder.build();
    }

    private long resolveRefreshTokenValidityPeriod(OAuthAppDO oAuthAppDO,
                                                   OAuthTokenReqMessageContext tokenMessageContext) {
        /*
        Prioritizes the refresh token expiry defined in OAuthTokenReqMessageContext.
        This honors the expiry value overridden at updateRefreshTokenValidityPeriodInMessageContext.
         */
        if (tokenMessageContext.getRefreshTokenValidityPeriodInMillis() > 0) {
            return TimeUnit.MILLISECONDS.toSeconds(tokenMessageContext.getRefreshTokenValidityPeriodInMillis());
        } else if (oAuthAppDO.getRefreshTokenExpiryTime() > 0) {
            return oAuthAppDO.getRefreshTokenExpiryTime();
        }
        return -1;
    }

    private long resolveRefreshTokenIssuedAt(OAuthTokenReqMessageContext tokenMessageContext) {

        return tokenMessageContext.getRefreshTokenIssuedTime() > 0 ? tokenMessageContext.getRefreshTokenIssuedTime() :
                -1;
    }

    private void setUserForEventBuilder(PreIssueAccessTokenEvent.Builder eventBuilder,
                                        AuthenticatedUser authenticatedUser, String clientID, String grantType) {

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
                // todo: fall back to a different identifier like username.
                //  Verify based on when this exception is thrown.
                LOG.debug(String.format(
                        "Error occurred while retrieving user id of the authorized user for application: " + clientID +
                                "for grantType: " + grantType), e);
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

        TokenRequest.Builder tokenRequestBuilder = new TokenRequest.Builder();
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

    private boolean isAccessTokenAuthorizedForUser(String grantType, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ActionExecutionRequestBuilderException {

        AuthorizationGrantHandler grantHandler =
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().get(grantType);

        try {
            return grantHandler.isOfTypeApplicationUser(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            throw new ActionExecutionRequestBuilderException(
                    "Failed to determine the authorized entity of the token for grant type: " +
                            grantType, e);
        }
    }

    private AccessToken getAccessToken(OAuthTokenReqMessageContext tokenMessageContext, OAuthAppDO oAuthAppDO,
                                       Map<String, Object> claimsToAdd)
            throws ActionExecutionRequestBuilderException {

        try {
            String issuer = getIssuer(tokenMessageContext);
            List<String> audience = getAudience(tokenMessageContext, oAuthAppDO);
            String tokenType = oAuthAppDO.getTokenType();

            AccessToken.Builder accessTokenBuilder = new AccessToken.Builder();

            handleStandardClaims(tokenMessageContext, tokenType, issuer, audience, accessTokenBuilder);
            handleSubjectClaim(tokenMessageContext.getAuthorizedUser(), oAuthAppDO, accessTokenBuilder);
            handleTokenBindingClaims(tokenMessageContext, accessTokenBuilder);
            handleActorClaim(tokenMessageContext, accessTokenBuilder);
            claimsToAdd.forEach(accessTokenBuilder::addClaim);
            return accessTokenBuilder.build();
        } catch (IdentityOAuth2Exception e) {
            throw new ActionExecutionRequestBuilderException(
                    "Failed to generate pre issue access token action request for application: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId() + " grant type: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getGrantType(), e);
        }
    }

    private OAuthAppDO getAppInformation(OAuthTokenReqMessageContext tokenMessageContext)
            throws ActionExecutionRequestBuilderException {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                    tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId(),
                    tokenMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new ActionExecutionRequestBuilderException(
                    "Failed to retrieve OAuth application with client id: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId() + " tenant domain: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain(), e);
        }
        return oAuthAppDO;
    }

    private String getIssuer(OAuthTokenReqMessageContext tokenMessageContext) throws IdentityOAuth2Exception {

        return OAuth2Util.getIdTokenIssuer(tokenMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());
    }

    private List<String> getAudience(OAuthTokenReqMessageContext tokenMessageContext, OAuthAppDO oAuthAppDO) {

        // Prioritize audience set in the context
        if (CollectionUtils.isNotEmpty(tokenMessageContext.getAudiences())) {
            return tokenMessageContext.getAudiences();
        } else {
            return OAuth2Util.getOIDCAudience(oAuthAppDO.getOauthConsumerKey(), oAuthAppDO);
        }
    }

    private void handleStandardClaims(OAuthTokenReqMessageContext tokenMessageContext, String tokenType,
                                      String issuer, List<String> audience, AccessToken.Builder accessTokenBuilder) {

        accessTokenBuilder.tokenType(tokenType)
                .addClaim(AccessToken.ClaimNames.ISS.getName(), issuer)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(),
                        tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId())
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(),
                        String.valueOf(tokenMessageContext.getProperty(OAuthConstants.UserType.USER_TYPE)))
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(),
                        tokenMessageContext.getValidityPeriod() / 1000)
                .addClaim(AccessToken.ClaimNames.AUD.getName(), audience)
                .scopes(Arrays.asList(tokenMessageContext.getScope()));
    }

    private void handleSubjectClaim(AuthenticatedUser authorizedUser, OAuthAppDO oAuthAppDO,
                                    AccessToken.Builder accessTokenBuilder) throws IdentityOAuth2Exception {

        String sub = authorizedUser.getAuthenticatedSubjectIdentifier();
        if (OAuth2Util.isPairwiseSubEnabledForAccessTokens()) {
            sub = OIDCClaimUtil.getSubjectClaim(sub, oAuthAppDO);
            accessTokenBuilder.addClaim(AccessToken.ClaimNames.SUBJECT_TYPE.getName(),
                    OIDCClaimUtil.getSubjectType(oAuthAppDO).getValue());
        }
        accessTokenBuilder.addClaim(AccessToken.ClaimNames.SUB.getName(), sub);
    }

    private void handleActorClaim(OAuthTokenReqMessageContext tokenMessageContext, AccessToken.Builder builder) {

        String actorStr = tokenMessageContext.getRequestedActor();

        if (StringUtils.isEmpty(actorStr)) {
            Object impersonator = tokenMessageContext.getProperty(OAuthConstants.IMPERSONATING_ACTOR);
            if (impersonator instanceof String) {
                actorStr = (String) impersonator;
            }
        }

        if (StringUtils.isNotEmpty(actorStr)) {
            Map<String, Object> actClaimValue = new HashMap<>();
            actClaimValue.put(AccessToken.ClaimNames.SUB.getName(), actorStr);
            builder.addClaim(AccessToken.ClaimNames.ACT.getName(), actClaimValue);
        }
    }

    private Map<String, Object> getAdditionalClaimsToAddToToken(OAuthTokenReqMessageContext tokenMessageContext)
            throws ActionExecutionRequestBuilderException {
         /*
         Directly return custom claims if pre-issue access token actions have been executed.
         This is to ensure that the custom claims added are incorporated in the refresh token flow.
         Moreover, this execution expects that the claim handlers executed at the token issuance flow
         does not incorporate any additional custom rules based on refresh grant.
         */
        if (tokenMessageContext.isPreIssueAccessTokenActionsExecuted()) {
            return tokenMessageContext.getAdditionalAccessTokenClaims();
        }

        try {
            CustomClaimsCallbackHandler claimsCallBackHandler =
                    ClaimHandlerUtil.getClaimsCallbackHandler(getAppInformation(tokenMessageContext));
            JWTClaimsSet claimsSet =
                    claimsCallBackHandler.handleCustomClaims(new JWTClaimsSet.Builder(), tokenMessageContext);
            return Optional.ofNullable(claimsSet).map(JWTClaimsSet::getClaims).orElseGet(HashMap::new);
        } catch (IdentityOAuth2Exception e) {
            throw new ActionExecutionRequestBuilderException(
                    "Failed to retrieve OIDC claim set for the access token for grant type: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getGrantType(), e);
        }
    }

    private void handleTokenBindingClaims(OAuthTokenReqMessageContext tokenMessageContext,
                                          AccessToken.Builder accessTokenBuilder) {

        if (tokenMessageContext.getTokenBinding() != null) {
            accessTokenBuilder.addClaim(AccessToken.ClaimNames.TOKEN_BINDING_REF.getName(),
                            tokenMessageContext.getTokenBinding().getBindingReference())
                    .addClaim(AccessToken.ClaimNames.TOKEN_BINDING_TYPE.getName(),
                            tokenMessageContext.getTokenBinding().getBindingType());
        }
    }

    public List<AllowedOperation> getAllowedOperations(Map<String, Object> oidcClaims, boolean isRefreshTokenAllowed) {

        List<String> removeOrReplacePaths = getRemoveOrReplacePaths(oidcClaims);

        List<String> replacePaths = new ArrayList<>(removeOrReplacePaths);
        replacePaths.add(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName());

        if (isRefreshTokenAllowed) {
            replacePaths.add(REFRESH_TOKEN_CLAIMS_PATH_PREFIX + RefreshToken.ClaimNames.EXPIRES_IN.getName());
        }

        AllowedOperation addOperation =
                createAllowedOperation(Operation.ADD, Arrays.asList(ACCESS_TOKEN_CLAIMS_PATH_PREFIX, SCOPES_PATH_PREFIX,
                        ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/"));
        AllowedOperation removeOperation = createAllowedOperation(Operation.REMOVE, removeOrReplacePaths);
        AllowedOperation replaceOperation = createAllowedOperation(Operation.REPLACE, replacePaths);

        return Arrays.asList(addOperation, removeOperation, replaceOperation);
    }

    private List<String> getRemoveOrReplacePaths(Map<String, Object> oidcClaims) {

        List<String> removeOrReplacePaths = new ArrayList<>();
        for (Map.Entry<String, Object> entry : oidcClaims.entrySet()) {

            String basePath = ACCESS_TOKEN_CLAIMS_PATH_PREFIX + entry.getKey();
            Object value = entry.getValue();

            removeOrReplacePaths.add(basePath);
            if (value instanceof String || value instanceof Number || value instanceof Boolean) {
                continue;
            }
            if (value instanceof List || value instanceof String[]) {
                removeOrReplacePaths.add(basePath + "/");
                continue;
            }

            // handle nested  objects
            if (value instanceof Map) {
                collectNestedClaimPaths(basePath, value, removeOrReplacePaths);
            }
        }
        removeOrReplacePaths.add(SCOPES_PATH_PREFIX);
        removeOrReplacePaths.add(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/");

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

    private Organization buildAccessTokenIssuedOrganization() {

        // Issuing organization is the tenant domain of the login tenant.
        // In Sub organizations, the parent organization.
        String accessTokenIssuingOrganization =
                IdentityTenantUtil.getTenantDomain(IdentityTenantUtil.getLoginTenantId());
        if (StringUtils.isEmpty(accessTokenIssuingOrganization)) {
            return null;
        }

        String organizationId = resolveOrganizationId(accessTokenIssuingOrganization);
        return buildOrganization(organizationId, accessTokenIssuingOrganization);
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
            LOG.error(
                    "Error while retrieving organization Id with tenant: " + tenantDomain, e);
        }
        return null;
    }
}
