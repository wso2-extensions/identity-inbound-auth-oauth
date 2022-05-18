/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.authz.validators.DefaultResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isValidTokenBinding;

/**
 * OAuth2 Service which is used to issue authorization codes or access tokens upon authorizing by the
 * user and issue/validateGrant access tokens.
 */
@SuppressWarnings("unused")
public class OAuth2Service extends AbstractAdmin {

    private static final Log log = LogFactory.getLog(OAuth2Service.class);

    /**
     * Process the authorization request and issue an authorization code or access token depending
     * on the Response Type available in the request.
     *
     * @param oAuth2AuthorizeReqDTO <code>OAuth2AuthorizeReqDTO</code> containing information about the authorization
     *                              request.
     * @return <code>OAuth2AuthorizeRespDTO</code> instance containing the access token/authorization code
     * or an error code.
     */
    public OAuth2AuthorizeRespDTO authorize(OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO) {

        if (log.isDebugEnabled()) {
            log.debug("Authorization Request received for user : " + oAuth2AuthorizeReqDTO.getUser() +
                    ", Client ID : " + oAuth2AuthorizeReqDTO.getConsumerKey() +
                    ", Authorization Response Type : " + oAuth2AuthorizeReqDTO.getResponseType() +
                    ", Requested callback URI : " + oAuth2AuthorizeReqDTO.getCallbackUrl() +
                    ", Requested Scope : " + OAuth2Util.buildScopeString(
                    oAuth2AuthorizeReqDTO.getScopes()));
        }

        try {
            AuthorizationHandlerManager authzHandlerManager =
                    AuthorizationHandlerManager.getInstance();
            return authzHandlerManager.handleAuthorization(oAuth2AuthorizeReqDTO);
        } catch (Exception e) {
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                    OAuthConstants.LogConstants.FAILED, "System error occurred.", "authorize-client", null);
            log.error("Error occurred when processing the authorization request. Returning an error back to client.",
                    e);
            OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
            authorizeRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            authorizeRespDTO.setErrorMsg("Error occurred when processing the authorization " +
                    "request. Returning an error back to client.");
            authorizeRespDTO.setCallbackURI(oAuth2AuthorizeReqDTO.getCallbackUrl());
            return authorizeRespDTO;
        }
    }

    /**
     * Check Whether the provided client_id and the callback URL are valid.
     *
     * @param clientId      client_id available in the request, Not null parameter.
     * @param callbackURI   callback_uri available in the request, can be null.
     * @return <code>OAuth2ClientValidationResponseDTO</code> bean with validity information,
     * callback, App Name, Error Code and Error Message when appropriate.
     *
     * Deprecated to use {{{@link #validateClientInfo(HttpServletRequest)}}}
     */
    @Deprecated
    public OAuth2ClientValidationResponseDTO validateClientInfo(String clientId, String callbackURI) {

        return new OAuth2ClientValidationResponseDTO();
    }

    /**
     * Check Whether the provided client information satisfy the response type validation
     *
     * @param request      The HttpServletRequest front the client.
     * @return <code>OAuth2ClientValidationResponseDTO</code> bean with validity information,
     * callback, App Name, Error Code and Error Message when appropriate.
     */
    public OAuth2ClientValidationResponseDTO validateClientInfo(HttpServletRequest request) {

        ResponseTypeRequestValidator validator = getResponseTypeRequestValidator(request);
        return validator.validateClientInfo(request);
    }

    /**
     * Check Whether the provided inputs from the client satisfy the response type validation
     *
     * @param request      The HttpServletRequest front the client.
     * @throws InvalidOAuthRequestException InvalidOAuthRequestException.
     */
    public void validateInputParameters(HttpServletRequest request) throws InvalidOAuthRequestException {

        ResponseTypeRequestValidator validator = getResponseTypeRequestValidator(request);
        validator.validateInputParameters(request);
    }

    /**
     * Issue access token in exchange to an Authorization Grant.
     *
     * @param tokenReqDTO <Code>OAuth2AccessTokenReqDTO</Code> representing the Access Token request
     * @return <Code>OAuth2AccessTokenRespDTO</Code> representing the Access Token response
     */
    public OAuth2AccessTokenRespDTO issueAccessToken(OAuth2AccessTokenReqDTO tokenReqDTO) {

        if (log.isDebugEnabled()) {
            log.debug("Access Token request received for Client ID " +
                    tokenReqDTO.getClientId() + ", User ID " + tokenReqDTO.getResourceOwnerUsername() +
                    ", Scope : " + Arrays.toString(tokenReqDTO.getScope()) + " and Grant Type : " +
                    tokenReqDTO.getGrantType());
        }

        try {
            AccessTokenIssuer tokenIssuer = AccessTokenIssuer.getInstance();
            return tokenIssuer.issue(tokenReqDTO);
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while issuing access token for Client ID : " +
                        tokenReqDTO.getClientId() + ", User ID: " + tokenReqDTO.getResourceOwnerUsername() +
                        ", Scope : " + Arrays.toString(tokenReqDTO.getScope()) + " and Grant Type : " +
                        tokenReqDTO.getGrantType(), e);
            }
            OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
            tokenRespDTO.setError(true);
            tokenRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            tokenRespDTO.setErrorMsg("Invalid Client");
            return tokenRespDTO;
        } catch (IdentityOAuth2ClientException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Error occurred while issuing access token for Client ID : %s , " +
                                "User ID: %s , Scope : %s  and Grant Type :  %s.", tokenReqDTO.getClientId(),
                        tokenReqDTO.getResourceOwnerUsername(), Arrays.toString(tokenReqDTO.getScope()),
                        tokenReqDTO.getGrantType()), e);
            }
            OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
            tokenRespDTO.setError(true);
            handleErrorCode(tokenRespDTO, e.getErrorCode());
            handleErrorMessage(tokenRespDTO, e.getMessage());
            return tokenRespDTO;
        } catch (Exception e) { // in case of an error, consider it as a system error
            log.error("Error occurred while issuing the access token for Client ID : " +
                    tokenReqDTO.getClientId() + ", User ID " + tokenReqDTO.getResourceOwnerUsername() +
                    ", Scope : " + Arrays.toString(tokenReqDTO.getScope()) + " and Grant Type : " +
                    tokenReqDTO.getGrantType(), e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                        OAuthConstants.LogConstants.FAILED, "System error occurred.", "issue-access-token", null);
            }
            OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
            tokenRespDTO.setError(true);
            if (e.getCause() != null && e.getCause().getCause() != null && (
                    e.getCause().getCause() instanceof SQLIntegrityConstraintViolationException || e.getCause()
                            .getCause() instanceof SQLException)) {
                tokenRespDTO.setErrorCode("sql_error");
            } else {
                tokenRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            }
            tokenRespDTO.setErrorMsg("Server Error");
            return tokenRespDTO;
        }
    }

    /**
     * Revoke tokens issued to OAuth clients
     *
     * @param revokeRequestDTO DTO representing consumerKey, consumerSecret and tokens[]
     * @return revokeRespDTO DTO representing success or failure message
     */
    public OAuthRevocationResponseDTO revokeTokenByOAuthClient(OAuthRevocationRequestDTO revokeRequestDTO) {

        //fix here remove associated cache entry
        OAuthRevocationResponseDTO revokeResponseDTO = new OAuthRevocationResponseDTO();
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        OAuthClientAuthnContext oAuthClientAuthnContext = revokeRequestDTO.getoAuthClientAuthnContext();

        if (!isClientAuthenticated(oAuthClientAuthnContext)) {
            try {
                // Returns the authentication failure error if the client doesn't support implicit grant
                if (!isImplicitGrantSupportedClient(revokeRequestDTO.getConsumerKey())) {
                    return buildErrorResponse(getErrorCode(oAuthClientAuthnContext),
                            getErrorMessage(oAuthClientAuthnContext));
                }
            } catch (IdentityOAuth2Exception  e) {
                log.error("Error occurred while checking client authentication.", e);
                return buildErrorResponse(OAuth2ErrorCodes.SERVER_ERROR, "Error occurred while revoking " +
                        "authorization grant for application.");
            } catch (InvalidOAuthClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Client Authentication failed.", e);
                }
                return buildErrorResponse(OAuth2ErrorCodes.INVALID_CLIENT, "Client Authentication failed.");
            }
        }

        //Invoke pre listeners

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPreTokenRevocationByClient(revokeRequestDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                        OAuthConstants.LogConstants.FAILED, "System error occurred.", "revoke-token", null);
                log.error(e);
                revokeResponseDTO.setError(true);
                revokeResponseDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
                revokeResponseDTO.setErrorMsg("Error occurred while revoking authorization grant for applications");
                return revokeResponseDTO;
            }
        }

        RefreshTokenValidationDataDO refreshTokenDO = null;
        AccessTokenDO accessTokenDO = null;

        try {
            if (StringUtils.isNotEmpty(revokeRequestDTO.getConsumerKey()) &&
                    StringUtils.isNotEmpty(revokeRequestDTO.getToken())) {

                boolean refreshTokenFirst = false;
                if (isRefreshTokenType(revokeRequestDTO)) {
                    refreshTokenFirst = true;
                }

                if (refreshTokenFirst) {
                    refreshTokenDO = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                            .validateRefreshToken(revokeRequestDTO.getConsumerKey(), revokeRequestDTO.getToken());

                    if (refreshTokenDO == null ||
                            StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState()) ||
                            !(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE
                                    .equals(refreshTokenDO.getRefreshTokenState()) ||
                                    OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                                            .equals(refreshTokenDO.getRefreshTokenState()))) {

                        accessTokenDO = OAuthTokenPersistenceFactory.getInstance()
                                .getAccessTokenDAO().getAccessToken(revokeRequestDTO.getToken(), true);
                        refreshTokenDO = null;
                    }

                } else {

                    accessTokenDO = OAuth2Util.findAccessToken(revokeRequestDTO.getToken(), true);
                    if (accessTokenDO == null) {

                        refreshTokenDO = OAuthTokenPersistenceFactory.getInstance()
                                .getTokenManagementDAO().validateRefreshToken(revokeRequestDTO.getConsumerKey(),
                                        revokeRequestDTO.getToken());

                        if (refreshTokenDO == null ||
                                StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState()) ||
                                !(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE
                                        .equals(refreshTokenDO.getRefreshTokenState()) ||
                                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                                                .equals(refreshTokenDO.getRefreshTokenState()))) {
                            Map<String, Object> params = new HashMap<>();
                            params.put("clientId", revokeRequestDTO.getConsumerKey());
                            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                                if (refreshTokenDO == null ||
                                        StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState())) {
                                    LoggerUtils.triggerDiagnosticLogEvent(
                                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                            OAuthConstants.LogConstants.FAILED, "Invalid token.", "revoke-token", null);
                                } else if (OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                                        .equals(refreshTokenDO.getRefreshTokenState())) {
                                    LoggerUtils.triggerDiagnosticLogEvent(
                                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                            OAuthConstants.LogConstants.SUCCESS, "Provided token is already revoked.",
                                            "revoke-token", null);
                                } else if (OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                                        .equals(refreshTokenDO.getRefreshTokenState())) {
                                    LoggerUtils.triggerDiagnosticLogEvent(
                                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                            OAuthConstants.LogConstants.SUCCESS, "Provided token is in inactive state.",
                                            "revoke-token", null);
                                }
                            }
                            refreshTokenDO = null;
                        }
                    }
                }

                String grantType = StringUtils.EMPTY;

                if (accessTokenDO != null) {
                    grantType = accessTokenDO.getGrantType();
                } else if (refreshTokenDO != null) {
                    grantType = refreshTokenDO.getGrantType();
                }

                if (!isClientAuthenticated(oAuthClientAuthnContext, grantType)) {
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        Map<String, Object> params = new HashMap<>();
                        params.put("clientId", revokeRequestDTO.getConsumerKey());
                        LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                OAuthConstants.LogConstants.FAILED, "OAuth client authentication is unsuccessful.",
                                "revoke-token", null);
                    }
                    OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
                    revokeRespDTO.setError(true);
                    revokeRespDTO.setErrorCode(getErrorCode(oAuthClientAuthnContext));
                    revokeRespDTO.setErrorMsg(getErrorMessage(oAuthClientAuthnContext));

                    invokePostRevocationListeners(revokeRequestDTO, revokeRespDTO, accessTokenDO,
                            refreshTokenDO);
                    return revokeRespDTO;
                }

                if (refreshTokenDO != null) {
                    String tokenBindingReference = NONE;
                    if (StringUtils.isNotBlank(refreshTokenDO.getTokenBindingReference())) {
                        tokenBindingReference = refreshTokenDO.getTokenBindingReference();
                    }
                    OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser(),
                            OAuth2Util.buildScopeString(refreshTokenDO.getScope()), tokenBindingReference);
                    OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser(),
                            OAuth2Util.buildScopeString(refreshTokenDO.getScope()));
                    OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser());
                    OAuthUtil.clearOAuthCache(refreshTokenDO.getAccessToken());
                    OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                            .revokeAccessTokens(new String[] { refreshTokenDO.getAccessToken() });
                    addRevokeResponseHeaders(revokeResponseDTO,
                            refreshTokenDO.getAccessToken(),
                            revokeRequestDTO.getToken(),
                            refreshTokenDO.getAuthorizedUser().toString());

                } else if (accessTokenDO != null) {
                    if (revokeRequestDTO.getConsumerKey().equals(accessTokenDO.getConsumerKey())) {
                        if ((OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey()).
                                isTokenBindingValidationEnabled()) && (!isValidTokenBinding(accessTokenDO.
                                getTokenBinding(), revokeRequestDTO.getRequest()))) {
                            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                                Map<String, Object> params = new HashMap<>();
                                params.put("clientId", accessTokenDO.getConsumerKey());
                                if (accessTokenDO.getTokenBinding() != null) {
                                    params.put("tokenBindingType", accessTokenDO.getTokenBinding().getBindingType());
                                    params.put("tokenBindingValue", accessTokenDO.getTokenBinding().getBindingValue());
                                }
                                Map<String, Object> configs = new HashMap<>();
                                configs.put("isTokenBindingValidationEnabled", "true");
                                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                        params, OAuthConstants.LogConstants.FAILED,
                                        "Valid token binding value not present in the request.",
                                        "validate-token-binding", configs);
                            }

                            revokeResponseDTO.setError(true);
                            revokeResponseDTO.setErrorCode(OAuth2ErrorCodes.ACCESS_DENIED);
                            revokeResponseDTO.setErrorMsg("Valid token binding value not present in the request.");
                            return revokeResponseDTO;
                        }
                        String tokenBindingReference = NONE;
                        if (accessTokenDO.getTokenBinding() != null && StringUtils
                                .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                            tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                        }
                        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                                OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                                OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser());
                        OAuthUtil.clearOAuthCache(accessTokenDO);
                        String scope = OAuth2Util.buildScopeString(accessTokenDO.getScope());
                        String userId = accessTokenDO.getAuthzUser().getUserId();
                        synchronized ((revokeRequestDTO.getConsumerKey() + ":" + userId + ":" + scope + ":"
                                + tokenBindingReference).intern()) {
                            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                                    .revokeAccessTokens(new String[]{accessTokenDO.getAccessToken()});
                        }
                        addRevokeResponseHeaders(revokeResponseDTO,
                                revokeRequestDTO.getToken(),
                                accessTokenDO.getRefreshToken(),
                                accessTokenDO.getAuthzUser().toString());
                    } else {
                        if (LoggerUtils.isDiagnosticLogsEnabled()) {
                            Map<String, Object> params = new HashMap<>();
                            params.put("clientId", accessTokenDO.getConsumerKey());
                            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                    params, OAuthConstants.LogConstants.FAILED, "Client is not authorized.",
                                    "validate-oauth-client", null);
                        }

                        throw new InvalidOAuthClientException("Unauthorized Client");
                    }
                }
                invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    Map<String, Object> params = new HashMap<>();
                    if (accessTokenDO != null) {
                        params.put("clientId", accessTokenDO.getConsumerKey());
                    }
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                            OAuthConstants.LogConstants.SUCCESS, "Token revocation is successful.", "revoke-tokens",
                            null);
                }
                return revokeResponseDTO;

            } else {
                Map<String, Object> params = new HashMap<>();
                if (StringUtils.isNotBlank(revokeRequestDTO.getConsumerKey())) {
                    params.put("clientId", revokeRequestDTO.getConsumerKey());
                } else {
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                OAuthConstants.LogConstants.FAILED, "'client_id' is empty in request.",
                                "validate-input-parameters", null);
                    }
                }
                if (StringUtils.isBlank(revokeRequestDTO.getToken())) {
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                                OAuthConstants.LogConstants.FAILED, "'token' is empty in request.",
                                "validate-input-parameters", null);
                    }
                }

                revokeResponseDTO.setError(true);
                revokeResponseDTO.setErrorCode(oAuthClientAuthnContext.getErrorCode());
                revokeResponseDTO.setErrorMsg(oAuthClientAuthnContext.getErrorMessage());
                invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
                return revokeResponseDTO;
            }

        } catch (InvalidOAuthClientException e) {
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                    OAuthConstants.LogConstants.FAILED, "Client is not authorized.", "validate-oauth-client", null);
            if (log.isDebugEnabled()) {
                log.debug("Unauthorized client.", e);
            }
            OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            revokeRespDTO.setErrorMsg("Unauthorized Client");
            invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
            return revokeRespDTO;
        } catch (IdentityException e) {
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                    OAuthConstants.LogConstants.FAILED, "System error occurred.", "revoke-tokens", null);
            log.error("Error occurred while revoking authorization grant for applications", e);
            OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            revokeRespDTO.setErrorMsg("Error occurred while revoking authorization grant for applications");
            invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
            return revokeRespDTO;
        }
    }

    private boolean isRefreshTokenType(OAuthRevocationRequestDTO revokeRequestDTO) {
        return StringUtils.equals(GrantType.REFRESH_TOKEN.toString(), revokeRequestDTO.getTokenType());
    }

    private void invokePostRevocationListeners(OAuthRevocationRequestDTO revokeRequestDTO, OAuthRevocationResponseDTO
            revokeResponseDTO, AccessTokenDO accessTokenDO, RefreshTokenValidationDataDO refreshTokenDO) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy
                        .onPostTokenRevocationByClient(revokeRequestDTO, revokeResponseDTO, accessTokenDO,
                                refreshTokenDO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred when invoking post token revoke listener ", e);
            }
        }
    }

    /**
     * Returns an array of claims of the authorized user. This is for the
     * OpenIDConnect user-end-point implementation.
     * <p/>
     * TODO : 1. Should return the userinfo response instead.
     * TODO : 2. Should create another service API for userinfo endpoint
     *
     * @param accessTokenIdentifier
     * @return
     * @throws IdentityException
     */
    public Claim[] getUserClaims(String accessTokenIdentifier) {

        OAuth2TokenValidationRequestDTO reqDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = reqDTO.new OAuth2AccessToken();
        accessToken.setTokenType("bearer");
        accessToken.setIdentifier(accessTokenIdentifier);
        reqDTO.setAccessToken(accessToken);
        OAuth2TokenValidationResponseDTO respDTO =
                new OAuth2TokenValidationService().validate(reqDTO);

        String username = respDTO.getAuthorizedUser();
        if (username == null) { // invalid token
            log.debug(respDTO.getErrorMsg());
            return new Claim[0];
        }
        String[] scope = respDTO.getScope();
        boolean isOICScope = false;
        for (String curScope : scope) {
            if ("openid".equals(curScope)) {
                isOICScope = true;
            }
        }
        if (!isOICScope) {
            if (log.isDebugEnabled()) {
                log.debug("AccessToken does not have the openid scope");
            }
            return new Claim[0];
        }

        // TODO : this code is ugly
        String profileName = "default"; // TODO : configurable
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenatUser = MultitenantUtils.getTenantAwareUsername(username);

        List<Claim> claimsList = new ArrayList<Claim>();

        // MUST claim
        // http://openid.net/specs/openid-connect-basic-1_0-22.html#id_res
        Claim subClaim = new Claim();
        subClaim.setClaimUri("sub");
        subClaim.setValue(username);
        claimsList.add(subClaim);

        try {
            UserStoreManager userStore =
                    IdentityTenantUtil.getRealm(tenantDomain, tenatUser)
                            .getUserStoreManager();
            // externel configured claims
            String[] claims = OAuthServerConfiguration.getInstance().getSupportedClaims();
            if (claims != null) {
                Map<String, String> extClaimsMap =
                        userStore.getUserClaimValues(username, claims,
                                profileName);
                for (Map.Entry<String, String> entry : extClaimsMap.entrySet()) {
                    Claim curClaim = new Claim();
                    curClaim.setClaimUri(entry.getKey());
                    curClaim.setValue(entry.getValue());
                    claimsList.add(curClaim);
                }
            }
            // default claims
            String[] defaultClaims = new String[3];
            defaultClaims[0] = "http://wso2.org/claims/emailaddress";
            defaultClaims[1] = "http://wso2.org/claims/givenname";
            defaultClaims[2] = "http://wso2.org/claims/lastname";
            String emailAddress = null;
            String firstName = null;
            String lastName = null;
            Map<String, String> defClaimsMap =
                    userStore.getUserClaimValues(username,
                            defaultClaims,
                            profileName);
            if (defClaimsMap.get(defaultClaims[0]) != null) {
                emailAddress = defClaimsMap.get(defaultClaims[0]);
                Claim email = new Claim();
                email.setClaimUri("email");
                email.setValue(emailAddress);
                claimsList.add(email);
                Claim prefName = new Claim();
                prefName.setClaimUri("preferred_username");
                prefName.setValue(emailAddress.split("@")[0]);
                claimsList.add(prefName);
            }
            if (defClaimsMap.get(defaultClaims[1]) != null) {
                firstName = defClaimsMap.get(defaultClaims[1]);
                Claim givenName = new Claim();
                givenName.setClaimUri("given_name");
                givenName.setValue(firstName);
                claimsList.add(givenName);
            }
            if (defClaimsMap.get(defaultClaims[2]) != null) {
                lastName = defClaimsMap.get(defaultClaims[2]);
                Claim familyName = new Claim();
                familyName.setClaimUri("family_name");
                familyName.setValue(lastName);
                claimsList.add(familyName);
            }
            if (firstName != null && lastName != null) {
                Claim name = new Claim();
                name.setClaimUri("name");
                name.setValue(firstName + " " + lastName);
                claimsList.add(name);
            }

        } catch (Exception e) {
            log.error("Error while reading user claims ", e);
        }

        Claim[] allClaims = new Claim[claimsList.size()];
        for (int i = 0; i < claimsList.size(); i++) {
            allClaims[i] = claimsList.get(i);
        }
        return allClaims;
    }

    public String getOauthApplicationState(String consumerKey) {

        try {
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(consumerKey);
            return appDO.getState();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while finding application state for application with client_id: " + consumerKey, e);
            return null;
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while finding an application associated with the given consumer key " +
                        consumerKey, e);
            }
            return null;
        }
    }

    public boolean isPKCESupportEnabled() {
        return OAuth2Util.isPKCESupportEnabled();
    }

    public List<TokenBinder> getSupportedTokenBinders() {

        return OAuth2ServiceComponentHolder.getInstance().getTokenBinders();
    }

    private void addRevokeResponseHeaders(OAuthRevocationResponseDTO revokeResponseDTP, String accessToken,
                                          String refreshToken, String authorizedUser) {

        if (OAuthServerConfiguration.getInstance().isRevokeResponseHeadersEnabled()) {
            List<ResponseHeader> respHeaders = new ArrayList<>();
            ResponseHeader header = new ResponseHeader();
            header.setKey("RevokedAccessToken");
            header.setValue(accessToken);
            respHeaders.add(header);
            header = new ResponseHeader();
            header.setKey("AuthorizedUser");
            header.setValue(authorizedUser);
            respHeaders.add(header);
            header = new ResponseHeader();
            header.setKey("RevokedRefreshToken");
            header.setValue(refreshToken);
            respHeaders.add(header);
            revokeResponseDTP.setResponseHeaders(respHeaders.toArray(new ResponseHeader[respHeaders.size()]));
        }
    }

    private boolean isClientAuthenticated(OAuthClientAuthnContext oAuthClientAuthnContext, String grantType) {
        return (oAuthClientAuthnContext != null &&
                oAuthClientAuthnContext.isAuthenticated() && !oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged
                ()) || StringUtils.equals(OAuthConstants.GrantTypes.IMPLICIT, grantType);
    }

    private boolean isClientAuthenticated(OAuthClientAuthnContext oAuthClientAuthnContext) {

        return oAuthClientAuthnContext != null &&
                oAuthClientAuthnContext.isAuthenticated() && !oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged();
    }

    private boolean isImplicitGrantSupportedClient(String consumerKey) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return (oAuthAppDO != null && oAuthAppDO.getGrantTypes().contains(OAuthConstants.GrantTypes.IMPLICIT));
    }

    private String getErrorMessage(OAuthClientAuthnContext oAuthClientAuthnContext) {
        String errorMessage = "Unauthorized Client";
        if (oAuthClientAuthnContext != null && StringUtils.isNotEmpty(oAuthClientAuthnContext.getErrorMessage())) {
            errorMessage = oAuthClientAuthnContext.getErrorMessage();
        }
        return errorMessage;
    }

    private String getErrorCode(OAuthClientAuthnContext oAuthClientAuthnContext) {
        String errorCode = OAuth2ErrorCodes.UNAUTHORIZED_CLIENT;
        if (oAuthClientAuthnContext != null && StringUtils.isNotEmpty(oAuthClientAuthnContext.getErrorCode())) {
            errorCode = oAuthClientAuthnContext.getErrorCode();
        }
        return errorCode;
    }

    private OAuthRevocationResponseDTO buildErrorResponse(String errorCode, String errorMessage) {

        OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
        revokeRespDTO.setError(true);
        revokeRespDTO.setErrorCode(errorCode);
        revokeRespDTO.setErrorMsg(errorMessage);
        return revokeRespDTO;
    }

    /**
     * Handles authorization requests denied by user.
     *
     * @param oAuth2Parameters OAuth parameters.
     * @return OAuthErrorDTO Error Data Transfer Object.
     */
    public OAuthErrorDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters) {

        try {
            return AuthorizationHandlerManager.getInstance().handleUserConsentDenial(oAuth2Parameters);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error in handling user consent denial for authentication request made by clientID: " +
                    oAuth2Parameters.getClientId(), e);
        }
        return null;
    }

    /**
     * Handles authentication failures.
     *
     * @param oauth2Params OAuth parameters.
     * @return OAuthErrorDTO Error Data Transfer Object.
     */
    public OAuthErrorDTO handleAuthenticationFailure(OAuth2Parameters oauth2Params) {

        try {
            return AuthorizationHandlerManager.getInstance().handleAuthenticationFailure(oauth2Params);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error in handling authentication failure for authentication request made by clientID: "
                    + oauth2Params.getClientId(), e);
        }
        return null;
    }

    private void handleErrorCode(OAuth2AccessTokenRespDTO tokenRespDTO, String errorCode) {

        if (StringUtils.isNotBlank(errorCode)) {
            tokenRespDTO.setErrorCode(errorCode);
        } else {
            tokenRespDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
        }
    }

    private void handleErrorMessage(OAuth2AccessTokenRespDTO tokenRespDTO, String errorMessage) {

        if (StringUtils.isNotBlank(errorMessage)) {
            tokenRespDTO.setErrorMsg(errorMessage);
        } else {
            tokenRespDTO.setErrorMsg("Invalid Client");
        }
    }

    private ResponseTypeRequestValidator getResponseTypeRequestValidator(HttpServletRequest request) {

        String responseType = request.getParameter(Constants.RESPONSE_TYPE);
        ResponseTypeRequestValidator validator = OAuth2ServiceComponentHolder.getInstance()
                .getResponseTypeRequestValidator(responseType);
        if (validator == null) {
            validator = new DefaultResponseTypeRequestValidator();
        }
        return validator;
    }
}

