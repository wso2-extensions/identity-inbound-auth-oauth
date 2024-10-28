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

package org.wso2.carbon.identity.oauth.action;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.Organization;
import org.wso2.carbon.identity.action.execution.model.Request;
import org.wso2.carbon.identity.action.execution.model.Tenant;
import org.wso2.carbon.identity.action.execution.model.User;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
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
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This class is responsible for building the action execution request for the pre issue access token action.
 */
public class PreIssueAccessTokenRequestBuilder implements ActionExecutionRequestBuilder {

    public static final String CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    public static final String SCOPES_PATH_PREFIX = "/accessToken/scopes/";
    private static final Log LOG = LogFactory.getLog(PreIssueAccessTokenRequestBuilder.class);

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(Map<String, Object> eventContext)
            throws ActionExecutionRequestBuilderException {

        OAuthTokenReqMessageContext tokenMessageContext =
                (OAuthTokenReqMessageContext) eventContext.get("tokenMessageContext");

        Map<String, Object> additionalClaimsToAddToToken = getAdditionalClaimsToAddToToken(tokenMessageContext);

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(tokenMessageContext, additionalClaimsToAddToToken));
        actionRequestBuilder.allowedOperations(getAllowedOperations(additionalClaimsToAddToToken));

        return actionRequestBuilder.build();
    }

    private Event getEvent(OAuthTokenReqMessageContext tokenMessageContext, Map<String, Object> claimsToAdd)
            throws ActionExecutionRequestBuilderException {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokenMessageContext.getOauth2AccessTokenReqDTO();
        AuthenticatedUser authorizedUser = tokenMessageContext.getAuthorizedUser();

        PreIssueAccessTokenEvent.Builder eventBuilder = new PreIssueAccessTokenEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(tokenReqDTO.getTenantDomain())),
                tokenReqDTO.getTenantDomain()));

        boolean isAuthorizedForUser = isAccessTokenAuthorizedForUser(tokenReqDTO.getGrantType(), tokenMessageContext);
        if (isAuthorizedForUser) {
            setUserForEventBuilder(eventBuilder, authorizedUser, tokenReqDTO.getClientId(), tokenReqDTO.getGrantType());
            setOrganizationForEventBuilder(eventBuilder, authorizedUser, tokenReqDTO.getClientId(),
                    tokenReqDTO.getGrantType());
            eventBuilder.userStore(new UserStore(authorizedUser.getUserStoreDomain()));
        }

        eventBuilder.accessToken(getAccessToken(tokenMessageContext, claimsToAdd));
        eventBuilder.request(getRequest(tokenReqDTO));

        return eventBuilder.build();
    }

    private void setUserForEventBuilder(PreIssueAccessTokenEvent.Builder eventBuilder, AuthenticatedUser user,
                                        String clientID, String grantType) {

        try {
            eventBuilder.user(new User(user.getUserId()));
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

    private void setOrganizationForEventBuilder(PreIssueAccessTokenEvent.Builder eventBuilder, AuthenticatedUser user,
                                                String clientID, String grantType) {

        try {
            String organizationId = user.getUserResidentOrganization();
            if (organizationId != null && !organizationId.isEmpty()) {
                String organizationName = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .getOrganizationNameById(user.getUserResidentOrganization());
                eventBuilder.organization(new Organization(user.getUserResidentOrganization(),
                        organizationName));
            }
        } catch (OrganizationManagementException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format(
                        "Error occurred while retrieving organization name of the authorized user for application: " +
                                clientID + "for grantType: " + grantType), e);
            }
        }
    }

    private Request getRequest(OAuth2AccessTokenReqDTO tokenRequestDTO) {

        TokenRequest.Builder tokenRequestBuilder = new TokenRequest.Builder();
        tokenRequestBuilder.clientId(tokenRequestDTO.getClientId());
        tokenRequestBuilder.grantType(tokenRequestDTO.getGrantType());
        tokenRequestBuilder.scopes(Arrays.asList(tokenRequestDTO.getScope()));

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

    private AccessToken getAccessToken(OAuthTokenReqMessageContext
                                               tokenMessageContext, Map<String, Object> claimsToAdd)
            throws ActionExecutionRequestBuilderException {

        try {
            OAuthAppDO oAuthAppDO = getAppInformation(tokenMessageContext);
            String issuer = getIssuer(tokenMessageContext);
            List<String> audience = getAudience(tokenMessageContext, oAuthAppDO);
            String tokenType = oAuthAppDO.getTokenType();

            AccessToken.Builder accessTokenBuilder = new AccessToken.Builder();

            handleStandardClaims(tokenMessageContext, tokenType, issuer, audience, accessTokenBuilder);
            handleSubjectClaim(tokenMessageContext.getAuthorizedUser(), oAuthAppDO, accessTokenBuilder);
            handleTokenBindingClaims(tokenMessageContext, accessTokenBuilder);
            claimsToAdd.forEach(accessTokenBuilder::addClaim);
            return accessTokenBuilder.build();
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new ActionExecutionRequestBuilderException(
                    "Failed to generate pre issue access token action request for application: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId() + " grant type: " +
                            tokenMessageContext.getOauth2AccessTokenReqDTO().getGrantType(), e);
        }
    }

    private OAuthAppDO getAppInformation(OAuthTokenReqMessageContext tokenMessageContext)
            throws InvalidOAuthClientException, IdentityOAuth2Exception {

        return OAuth2Util.getAppInformationByClientId(
                tokenMessageContext.getOauth2AccessTokenReqDTO().getClientId(),
                tokenMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());
    }

    private String getIssuer(OAuthTokenReqMessageContext tokenMessageContext) throws IdentityOAuth2Exception {

        return OAuth2Util.getIdTokenIssuer(tokenMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());
    }

    private List<String> getAudience(OAuthTokenReqMessageContext tokenMessageContext, OAuthAppDO oAuthAppDO) {

        if (tokenMessageContext.isPreIssueAccessTokenActionsExecuted()) {
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
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
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

    public List<AllowedOperation> getAllowedOperations(Map<String, Object> oidcClaims) {

        List<String> removeOrReplacePaths = getRemoveOrReplacePaths(oidcClaims);

        List<String> replacePaths = new ArrayList<>(removeOrReplacePaths);
        replacePaths.add(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName());

        AllowedOperation addOperation =
                createAllowedOperation(Operation.ADD, Arrays.asList(CLAIMS_PATH_PREFIX, SCOPES_PATH_PREFIX,
                        CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/"));
        AllowedOperation removeOperation = createAllowedOperation(Operation.REMOVE, removeOrReplacePaths);
        AllowedOperation replaceOperation = createAllowedOperation(Operation.REPLACE, replacePaths);

        return Arrays.asList(addOperation, removeOperation, replaceOperation);
    }

    private List<String> getRemoveOrReplacePaths(Map<String, Object> oidcClaims) {

        List<String> removeOrReplacePaths = oidcClaims.entrySet().stream()
                .filter(entry -> entry.getValue() instanceof String || entry.getValue() instanceof Number ||
                        entry.getValue() instanceof Boolean || entry.getValue() instanceof List ||
                        entry.getValue() instanceof String[])
                .map(this::generatePathForClaim)
                .collect(Collectors.toList());

        removeOrReplacePaths.add(SCOPES_PATH_PREFIX);
        removeOrReplacePaths.add(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/");
        return removeOrReplacePaths;
    }

    private String generatePathForClaim(Map.Entry<String, Object> entry) {

        String basePath = CLAIMS_PATH_PREFIX + entry.getKey();
        if (entry.getValue() instanceof List || entry.getValue() instanceof String[]) {
            basePath += "/";
        }
        return basePath;
    }

    private AllowedOperation createAllowedOperation(Operation op, List<String> paths) {

        AllowedOperation operation = new AllowedOperation();
        operation.setOp(op);
        operation.setPaths(new ArrayList<>(paths));
        return operation;
    }

}
