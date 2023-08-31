/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.ActionIDs.VALIDATE_OAUTH_CLIENT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REDIRECT_URI;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUEST_URI;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validateRequestTenantDomain;

/**
 * The abstract implementation of the ResponseTypeRequestValidator.
 */
public abstract class AbstractResponseTypeRequestValidator implements ResponseTypeRequestValidator {

    private static final Log log = LogFactory.getLog(AbstractResponseTypeRequestValidator.class);
    private static final String APP_STATE_ACTIVE = "ACTIVE";
    protected final List<String> parametersToValidate = new ArrayList<>();

    @Override
    public void validateInputParameters(HttpServletRequest request) throws InvalidOAuthRequestException {

        if (StringUtils.isBlank(request.getParameter(CLIENT_ID))) {
            if (log.isDebugEnabled()) {
                log.debug("Client Id is not present in the authorization request");
            }
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAUTH_INBOUND_SERVICE, VALIDATE_INPUT_PARAMS)
                    .resultMessage("Client Id is not present in the authorization request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            throw new InvalidOAuthRequestException("Client Id is not present in the authorization request",
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_CLIENT);
        }


        if (parametersToValidate.contains(REDIRECT_URI) && StringUtils.isBlank(request.getParameter(REQUEST_URI)) &&
                StringUtils.isBlank(request.getParameter(REDIRECT_URI))) {
            if (log.isDebugEnabled()) {
                log.debug("Redirect URI is not present in the authorization request");
            }
            LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                    OAUTH_INBOUND_SERVICE, VALIDATE_INPUT_PARAMS)
                    .resultMessage("Redirect URI is not present in the authorization request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            throw new InvalidOAuthRequestException(
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.INVALID_REDIRECT_URI,
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REDIRECT_URI);
        }
    }

    @Override
    public OAuth2ClientValidationResponseDTO validateClientInfo(HttpServletRequest request) {

        String clientId = request.getParameter(CLIENT_ID);
        String callbackURI = request.getParameter(REDIRECT_URI);

        if (log.isDebugEnabled()) {
            log.debug("Validate Client information request for client_id : " + clientId + " , callback_uri " +
                    callbackURI);
        }

        try {
            String appTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);
            validateRequestTenantDomain(appTenantDomain);
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(OAUTH_INBOUND_SERVICE,
                        VALIDATE_INPUT_PARAMS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
            }
            if (StringUtils.isBlank(clientId)) {
                // diagnosticLogBuilder will be null if diagnostic logs are disabled.
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("client_id cannot be empty.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new InvalidOAuthClientException("Invalid client_id. No OAuth application has been registered " +
                        "with the given client_id");
            }
            if (diagnosticLogBuilder != null) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, clientId);
            }
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientId);
            String appState = appDO.getState();

            if (StringUtils.isEmpty(appState)) {
                if (log.isDebugEnabled()) {
                    log.debug("A valid OAuth client could not be found for client_id: " + clientId);
                }
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("A valid OAuth application could not be found for given " +
                            "client_id.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new InvalidOAuthClientException("A valid OAuth client could not be found for client_id: " +
                        Encode.forHtml(clientId));
            }

            if (!appState.equalsIgnoreCase(APP_STATE_ACTIVE)) {
                if (log.isDebugEnabled()) {
                    log.debug("App is not in active state in client ID: " + clientId + ". App state is: " + appState);
                }
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("OAuth application is not in active state.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new InvalidOAuthClientException("Oauth application is not in active state.");
            }
            return validateCallBack(clientId, callbackURI, appDO);
        } catch (InvalidOAuthClientException e) {
            // There is no such Client ID being registered. So it is a request from an invalid client.
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving the Application Information", e);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAUTH_INBOUND_SERVICE, VALIDATE_OAUTH_CLIENT)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .resultMessage("Cannot find an application associated with the given client_id.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CLIENT);
            validationResponseDTO.setErrorMsg(e.getMessage());
            return validationResponseDTO;
        } catch (IdentityOAuth2Exception e) {
            log.error("Error when reading the Application Information.", e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAUTH_INBOUND_SERVICE, VALIDATE_INPUT_PARAMS)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("Error when reading the Application Information.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            validationResponseDTO.setErrorMsg("Error when processing the authorization request.");
            return validationResponseDTO;
        }
    }

    private OAuth2ClientValidationResponseDTO validateCallBack(String clientId, String callbackURI, OAuthAppDO appDO) {

        if (!parametersToValidate.contains(REDIRECT_URI)) {
            OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
            validationResponseDTO.setValidClient(true);
            return validationResponseDTO;
        }

        OAuth2ClientValidationResponseDTO validationResponseDTO = new OAuth2ClientValidationResponseDTO();
        if (StringUtils.isEmpty(appDO.getGrantTypes()) || (StringUtils.isEmpty(appDO.getCallbackUrl()))) {
            if (log.isDebugEnabled()) {
                log.debug("Registered App found for the given Client Id : " + clientId + " ,App Name : " + appDO
                        .getApplicationName() + ", does not support the requested grant type.");
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAUTH_INBOUND_SERVICE, VALIDATE_INPUT_PARAMS)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .configParam(OAuthConstants.LogConstants.ConfigKeys.CALLBACK_URI, appDO.getCallbackUrl())
                        .configParam(OAuthConstants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                appDO.getGrantTypes())
                        .resultMessage("The OAuth client is not authorized to use the requested grant type.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
            validationResponseDTO.setErrorMsg("not.authorized.to.use.requested.grant.type");
            return validationResponseDTO;
        }

        OAuth2Util.setClientTenatId(IdentityTenantUtil.getTenantId(appDO.getAppOwner().getTenantDomain()));

        // Valid Client, No callback has provided. Use the callback provided during the registration.
        if (callbackURI == null) {
            validationResponseDTO.setValidClient(true);
            validationResponseDTO.setCallbackURL(appDO.getCallbackUrl());
            return validationResponseDTO;
        }

        if (log.isDebugEnabled()) {
            log.debug("Registered App found for the given Client Id : " + clientId + " ,App Name : " + appDO
                    .getApplicationName() + ", Callback URL : " + appDO.getCallbackUrl());
        }

        if (validateCallbackURI(callbackURI, appDO)) {
            validationResponseDTO.setValidClient(true);
            validationResponseDTO.setCallbackURL(callbackURI);
        } else {    // Provided callback URL does not match the registered callback url.
            log.warn("Provided Callback URL does not match with the registered one.");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAUTH_INBOUND_SERVICE, VALIDATE_INPUT_PARAMS)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REDIRECT_URI, callbackURI)
                        .configParam(OAuthConstants.LogConstants.ConfigKeys.CALLBACK_URI, appDO.getCallbackUrl())
                        .resultMessage("redirect_uri in request does not match with the registered one.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            validationResponseDTO.setValidClient(false);
            validationResponseDTO.setErrorCode(OAuth2ErrorCodes.INVALID_CALLBACK);
            validationResponseDTO.setErrorMsg(
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.CALLBACK_NOT_MATCH);
        }
        return validationResponseDTO;
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

        if (callbackURI == null) {
            return false;
        }
        String regexp = null;
        String registeredCallbackUrl = oauthApp.getCallbackUrl();
        if (registeredCallbackUrl.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            regexp = registeredCallbackUrl.substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
        }
        if (log.isDebugEnabled()) {
            log.debug("Comparing provided callback URL: " + callbackURI + " with configured callback: " +
                    registeredCallbackUrl);
        }
        if (callbackURI.matches(OAuthConstants.LOOPBACK_IP_REGEX)) {
            callbackURI = callbackURI.replaceFirst(OAuthConstants.LOOPBACK_IP_PORT_REGEX, StringUtils.EMPTY);
            if (regexp != null) {
                regexp = regexp.replaceAll(OAuthConstants.LOOPBACK_IP_PORT_REGEX, StringUtils.EMPTY);
                if (!callbackURI.matches(regexp)) {
                    log.debug("Regex might contain port number capture group/groups for loopback ip address");
                    return false;
                }
                return true;
            }
            registeredCallbackUrl =
                    registeredCallbackUrl.replaceFirst(OAuthConstants.LOOPBACK_IP_PORT_REGEX, StringUtils.EMPTY);
        }
        return (regexp != null && callbackURI.matches(regexp)) || registeredCallbackUrl.equals(callbackURI);
    }
}
