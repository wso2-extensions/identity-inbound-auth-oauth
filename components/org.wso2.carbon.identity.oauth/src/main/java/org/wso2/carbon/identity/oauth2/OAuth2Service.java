/*
 * Copyright (c) 2013, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
import org.owasp.encoder.Encode;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
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
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.validators.DefaultResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
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
import org.wso2.carbon.utils.DiagnosticLog;
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
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validateRequestTenantDomain;

/**
 * OAuth2 Service which is used to issue authorization codes or access tokens upon authorizing by the
 * user and issue/validateGrant access tokens.
 */
@SuppressWarnings("unused")
public class OAuth2Service extends AbstractAdmin {

    private static final Log log = LogFactory.getLog(OAuth2Service.class);
    private static final String APP_STATE_ACTIVE = "ACTIVE";

    /**
     * Process the authorization request and issue an authorization code or access token depending
     * on the Response Type available in the request.
     *
     * @param oAuth2AuthorizeReqDTO <code>OAuth2AuthorizeReqDTO</code> containing information about the authorization
     *                              request.
     * @return <code>OAuth2AuthorizeRespDTO</code> instance containing the access token/authorization code
     * or an error code.
     */
    @Deprecated
    /**
     * @deprecated Avoid using this, use {@link #authorize(OAuthAuthzReqMessageContext, OAuth2AuthorizeReqDTO)
     * authorize} method instead.
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
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, "authorize-client");
            diagnosticLogBuilder.resultMessage("System error occurred.")
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
     * Process the authorization request and issue an authorization code or access token depending
     * on the Response Type available in the request.
     *
     * @param authzReqMsgCtx authzReqMsgCtx.
     * @return <code>OAuth2AuthorizeRespDTO</code> instance containing the access token/authorization code
     * or an error code.
     */
    public OAuth2AuthorizeRespDTO authorize(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();
        if (log.isDebugEnabled()) {
            log.debug("Authorization Request received for user : " + authzReqDTO.getUser() +
                    ", Client ID : " + authzReqDTO.getConsumerKey() +
                    ", Authorization Response Type : " + authzReqDTO.getResponseType() +
                    ", Requested callback URI : " + authzReqDTO.getCallbackUrl() +
                    ", Requested Scopes : " + OAuth2Util.buildScopeString(authzReqMsgCtx.getApprovedScope()) +
                    ", Approved Scopes : " + OAuth2Util.buildScopeString(
                    authzReqDTO.getScopes()));
        }
        try {
            AuthorizationHandlerManager authzHandlerManager = AuthorizationHandlerManager.getInstance();
            return authzHandlerManager.handleAuthorization(authzReqMsgCtx);
        } catch (Exception e) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, "authorize-client")
                    .resultMessage("Error occurred when processing the authorization request.")
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            log.error("Error occurred when processing the authorization request. Returning an error back to client.",
                    e);
            OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
            authorizeRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            authorizeRespDTO.setErrorMsg("Error occurred when processing the authorization " +
                    "request. Returning an error back to client.");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            return authorizeRespDTO;
        }
    }

    /**
     * Handle authorization request (validate requested scopes) before the consent page.
     * We return a OAuthAuthzReqMessageContext object instead of a response object here since we use this context across
     * the scope validation (before consent) and issuing code.
     *
     * @param authzReqDTO OAuth2AuthorizeReqDTO
     * @return OAuthAuthzReqMessageContext
     */
    public OAuthAuthzReqMessageContext validateScopesBeforeConsent(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, IdentityOAuth2UnauthorizedScopeException, InvalidOAuthClientException {

        AuthorizationHandlerManager authzHandlerManager = AuthorizationHandlerManager.getInstance();
        return authzHandlerManager.validateScopesBeforeConsent(authzReqDTO);
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

        OAuth2ClientValidationResponseDTO validationResponseDTO =
                new OAuth2ClientValidationResponseDTO();

        if (log.isDebugEnabled()) {
            log.debug("Validate Client information request for client_id : " + clientId + " and callback_uri " +
                    callbackURI);
        }

        try {
            String appTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);
            validateRequestTenantDomain(appTenantDomain);

            if (StringUtils.isBlank(clientId)) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .resultMessage("client_id cannot be empty.")
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
                }
                throw new InvalidOAuthClientException("Invalid client_id. No OAuth application has been registered " +
                        "with the given client_id");
            }
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String appState = appDO.getState();

            if (StringUtils.isEmpty(appState)) {
                if (log.isDebugEnabled()) {
                    log.debug("A valid OAuth client could not be found for client_id: " + clientId);
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .resultMessage("A valid OAuth application could not be found for given client_id.")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
                }
                throw new InvalidOAuthClientException("A valid OAuth client could not be found for client_id: " +
                        Encode.forHtml(clientId));
            }

            if (!appState.equalsIgnoreCase(APP_STATE_ACTIVE)) {
                if (log.isDebugEnabled()) {
                    log.debug("App is not in active state in client ID: " + clientId + ". App state is: " + appState);
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .resultMessage("OAuth application is not in active state.")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                throw new InvalidOAuthClientException("Oauth application is not in active state");
            }

            if (StringUtils.isEmpty(appDO.getGrantTypes()) || StringUtils.isEmpty(appDO.getCallbackUrl())) {
                if (log.isDebugEnabled()) {
                    log.debug("Registered App found for the given Client Id : " + clientId + " ,App Name : " + appDO
                            .getApplicationName() + ", does not support the requested grant type.");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .resultMessage("The OAuth client is not authorized to use the requested grant type.")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                            .configParam("callback URI", callbackURI)
                            .configParam("supported grant types", appDO.getGrantTypes())
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                validationResponseDTO.setValidClient(false);
                validationResponseDTO.setErrorCode(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
                validationResponseDTO
                        .setErrorMsg("The authenticated client is not authorized to use this authorization grant type");
                return validationResponseDTO;
            }

            OAuth2Util.setClientTenatId(IdentityTenantUtil.getTenantId(appDO.getUser().getTenantDomain()));

            // Valid Client, No callback has provided. Use the callback provided during the registration.
            if (callbackURI == null) {
                validationResponseDTO.setValidClient(true);
                validationResponseDTO.setCallbackURL(appDO.getCallbackUrl());
                validationResponseDTO.setApplicationName(appDO.getApplicationName());
                validationResponseDTO.setPkceMandatory(appDO.isPkceMandatory());
                validationResponseDTO.setPkceSupportPlain(appDO.isPkceSupportPlain());
                return validationResponseDTO;
            }

            if (log.isDebugEnabled()) {
                log.debug("Registered App found for the given Client Id : " + clientId + " ,App Name : " + appDO
                        .getApplicationName() + ", Callback URL : " + appDO.getCallbackUrl());
            }

            if (validateCallbackURI(callbackURI, appDO)) {
                validationResponseDTO.setValidClient(true);
                validationResponseDTO.setApplicationName(appDO.getApplicationName());
                validationResponseDTO.setCallbackURL(callbackURI);
                validationResponseDTO.setPkceMandatory(appDO.isPkceMandatory());
                validationResponseDTO.setPkceSupportPlain(appDO.isPkceSupportPlain());
                return validationResponseDTO;
            } else {    // Provided callback URL does not match the registered callback url.
                log.warn("Provided Callback URL does not match with the registered URL.");
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .resultMessage("redirect_uri in request does not match with the registered redirect URI.")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                            .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, callbackURI)
                            .inputParam(LogConstants.InputKeys.APPLICATION_NAME, appDO.getApplicationName())
                            .inputParam("registered redirect URI", appDO.getCallbackUrl())
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                validationResponseDTO.setValidClient(false);
                validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CALLBACK);
                validationResponseDTO.setErrorMsg(
                        OAuthConstants.OAuthError.AuthorizationResponsei18nKey.CALLBACK_NOT_MATCH);
                return validationResponseDTO;
            }
        } catch (InvalidOAuthClientException e) {
            // There is no such Client ID being registered. So it is a request from an invalid client.
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving the Application Information", e);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT)
                        .resultMessage("Cannot find an application associated with the given client id.")
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            validationResponseDTO.setErrorMsg(e.getMessage());
            return validationResponseDTO;
        } catch (IdentityOAuth2Exception e) {
            log.error("Error when reading the Application Information.", e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                        .resultMessage("Server error occurred.")
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            validationResponseDTO.setErrorMsg("Error when processing the authorization request.");
            return validationResponseDTO;
        }
    }

    /**
     * Validate Client with a callback url in the request.
     *
     * @param callbackURI callback url in the request.
     * @param oauthApp OAuth application data object
     * @return boolean If application callback url is defined as a regexp check weather it matches the given url
     * Or check weather callback urls are equal
     */
    private boolean validateCallbackURI(String callbackURI, OAuthAppDO oauthApp) {
        String regexp = null;
        String registeredCallbackUrl = oauthApp.getCallbackUrl();
        if (registeredCallbackUrl.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            regexp = registeredCallbackUrl.substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
        }
        if (log.isDebugEnabled()) {
            log.debug("Comparing provided callback URL: " + callbackURI + " with configured callback: " +
                    registeredCallbackUrl);
        }
        return (regexp != null && callbackURI.matches(regexp)) || registeredCallbackUrl.equals(callbackURI);
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
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.ISSUE_ACCESS_TOKEN)
                        .resultMessage("System error occurred.")
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                        .inputParam(LogConstants.InputKeys.USER, tokenReqDTO.getResourceOwnerUsername())
                        .inputParam(LogConstants.InputKeys.SCOPE, Arrays.toString(tokenReqDTO.getScope()))
                        .inputParam("grant type", tokenReqDTO.getGrantType())
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
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
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.REVOKE_TOKEN)
                            .resultMessage("System error occurred.")
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, revokeRequestDTO.getConsumerKey())
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
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
                    refreshTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                            .getVerifiedRefreshToken(revokeRequestDTO.getToken(), revokeRequestDTO.getConsumerKey());
                    if (refreshTokenDO == null ||
                            StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState()) ||
                            !(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE
                                    .equals(refreshTokenDO.getRefreshTokenState()) ||
                                    OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                                            .equals(refreshTokenDO.getRefreshTokenState()))) {
                        accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                                .getVerifiedAccessToken(revokeRequestDTO.getToken(), true);
                        refreshTokenDO = null;
                    }
                } else {
                    accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                            .getVerifiedAccessToken(revokeRequestDTO.getToken(), true);
                    if (accessTokenDO == null) {
                        refreshTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                                .getVerifiedRefreshToken(revokeRequestDTO.getToken(),
                                        revokeRequestDTO.getConsumerKey());
                        if (refreshTokenDO == null ||
                                StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState()) ||
                                !(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE
                                        .equals(refreshTokenDO.getRefreshTokenState()) ||
                                        OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED
                                                .equals(refreshTokenDO.getRefreshTokenState()))) {
                            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                                        DiagnosticLog.DiagnosticLogBuilder(
                                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                        OAuthConstants.LogConstants.ActionIDs.REVOKE_TOKEN);
                                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID,
                                        revokeRequestDTO.getConsumerKey())
                                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                                if (refreshTokenDO == null ||
                                        StringUtils.isEmpty(refreshTokenDO.getRefreshTokenState())) {
                                    diagnosticLogBuilder.resultMessage("Invalid token.");
                                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                                } else if (OAuthConstants.TokenStates.TOKEN_STATE_REVOKED
                                        .equals(refreshTokenDO.getRefreshTokenState())) {
                                    diagnosticLogBuilder.resultMessage("Provided token is already revoked.");
                                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                                } else if (OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE
                                        .equals(refreshTokenDO.getRefreshTokenState())) {
                                    diagnosticLogBuilder.resultMessage("Provided token is in inactive state.");
                                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
                        LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                                OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                OAuthConstants.LogConstants.ActionIDs.REVOKE_TOKEN)
                                .resultMessage("OAuth client authentication is unsuccessful.")
                                .inputParam(LogConstants.InputKeys.CLIENT_ID, revokeRequestDTO.getConsumerKey())
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED));
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
                    if (refreshTokenDO.getAccessToken() != null) {
                        OAuthUtil.clearOAuthCache(refreshTokenDO.getAccessToken());
                    }
                    getRevocationProcessor().revokeRefreshToken(revokeRequestDTO, refreshTokenDO);
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
                                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                                        DiagnosticLog.DiagnosticLogBuilder(
                                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_TOKEN_BINDING)
                                        .resultMessage("Valid token binding value not present in the request.")
                                        .inputParam(LogConstants.InputKeys.CLIENT_ID, accessTokenDO.getConsumerKey())
                                        .configParam("is token binding validation enabled", "true")
                                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                                if (accessTokenDO.getTokenBinding() != null) {
                                    diagnosticLogBuilder.inputParam("token binding type",
                                                    accessTokenDO.getTokenBinding().getBindingType())
                                            .inputParam("token binding value", accessTokenDO.getTokenBinding()
                                                    .getBindingValue());
                                }
                                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
                            getRevocationProcessor().revokeAccessToken(revokeRequestDTO, accessTokenDO);
                        }
                        addRevokeResponseHeaders(revokeResponseDTO,
                                revokeRequestDTO.getToken(),
                                accessTokenDO.getRefreshToken(),
                                accessTokenDO.getAuthzUser().toString());
                    } else {
                        if (LoggerUtils.isDiagnosticLogsEnabled()) {
                            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT)
                                    .resultMessage("Client is not authorized.")
                                    .inputParam(LogConstants.InputKeys.CLIENT_ID, accessTokenDO.getConsumerKey())
                                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                        }

                        throw new InvalidOAuthClientException("Unauthorized Client");
                    }
                }
                invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.REVOKE_TOKEN)
                            .resultMessage("Token revocation is successful.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                    if (accessTokenDO != null) {
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID,
                                accessTokenDO.getConsumerKey());
                    }
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return revokeResponseDTO;

            } else {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                }
                Map<String, Object> params = new HashMap<>();
                if (StringUtils.isNotBlank(revokeRequestDTO.getConsumerKey()) && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID,
                            revokeRequestDTO.getConsumerKey());
                } else {
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("'client_id' is empty in request.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                }
                if (StringUtils.isBlank(revokeRequestDTO.getToken())) {
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("'token' is empty in request.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                }
                revokeResponseDTO.setError(true);
                revokeResponseDTO.setErrorCode(oAuthClientAuthnContext.getErrorCode());
                revokeResponseDTO.setErrorMsg(oAuthClientAuthnContext.getErrorMessage());
                invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
                return revokeResponseDTO;
            }

        } catch (InvalidOAuthClientException e) {
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT)
                    .resultMessage("Client is not authorized.")
                    .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
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
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.REVOKE_TOKEN)
                    .resultMessage("System error occurred.")
                    .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            log.error("Error occurred while revoking authorization grant for applications", e);
            OAuthRevocationResponseDTO revokeRespDTO = new OAuthRevocationResponseDTO();
            revokeRespDTO.setError(true);
            revokeRespDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            revokeRespDTO.setErrorMsg("Error occurred while revoking authorization grant for applications");
            invokePostRevocationListeners(revokeRequestDTO, revokeResponseDTO, accessTokenDO, refreshTokenDO);
            return revokeRespDTO;
        }
    }

    /**
     * Get the revocation processor.
     *
     * @return OAuth2RevocationProcessor
     */
    private OAuth2RevocationProcessor getRevocationProcessor() {

        return OAuth2ServiceComponentHolder.getInstance().getRevocationProcessor();
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

