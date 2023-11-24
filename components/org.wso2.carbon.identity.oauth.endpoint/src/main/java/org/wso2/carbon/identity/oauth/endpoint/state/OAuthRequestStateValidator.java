/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.state;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.exception.AccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.INITIAL_REQUEST;
import static org.wso2.carbon.identity.oauth.endpoint.state.OAuthAuthorizeState.USER_CONSENT_RESPONSE;
import static org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil.getOAuth2Service;

/**
 * This class validate the OAuth request state.
 */
public class OAuthRequestStateValidator {

    private static final Log log = LogFactory.getLog(OAuthRequestStateValidator.class);

    public OAuthAuthorizeState validateAndGetState(OAuthMessage oAuthMessage) throws InvalidRequestParentException {

        if (handleToCommonauthState(oAuthMessage)) {
            return OAuthAuthorizeState.PASSTHROUGH_TO_COMMONAUTH;
        }

        validateRequest(oAuthMessage);

        if (oAuthMessage.isInitialRequest()) {
            validateInputParameters(oAuthMessage);
            return INITIAL_REQUEST;
        } else if (oAuthMessage.isAuthResponseFromFramework()) {
            return AUTHENTICATION_RESPONSE;
        } else if (oAuthMessage.isConsentResponseFromUser()) {
            return USER_CONSENT_RESPONSE;
        } else {
            return handleInvalidRequest();
        }
    }

    private OAuthAuthorizeState handleInvalidRequest() throws InvalidRequestException {
        // Invalid request
        if (log.isDebugEnabled()) {
            log.debug("Invalid authorization request");
        }

        throw new InvalidRequestException("Invalid authorization request", OAuth2ErrorCodes.INVALID_REQUEST,
                OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST);
    }

    private boolean handleToCommonauthState(OAuthMessage oAuthMessage) {

        return (oAuthMessage.isRequestToCommonauth() && oAuthMessage.getFlowStatus() == null);
    }

    private void validateRequest(OAuthMessage oAuthMessage)
            throws InvalidRequestParentException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                    .inputParams(oAuthMessage.getRequest().getParameterMap())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        validateRepeatedParameters(oAuthMessage);

        if (oAuthMessage.getResultFromLogin() != null && oAuthMessage.getResultFromConsent() != null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization request.\'SessionDataKey\' found in request as parameter and " +
                        "attribute, and both have non NULL objects in cache");
            }
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null if diagnostic logs are disabled.
                diagnosticLogBuilder.resultMessage("Invalid 'SessionDataKey' parameter in authorization request.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new InvalidRequestException("Invalid authorization request", OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_AUTHORIZATION_REQUEST);

        } else if (oAuthMessage.getClientId() == null && oAuthMessage.getResultFromLogin() == null && oAuthMessage
                .getResultFromConsent() == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization request.\'SessionDataKey\' not found in request as parameter or " +
                        "attribute, and client_id parameter cannot be found in request");
            }
            if (diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Invalid 'client_id' and 'SessionDataKey' parameters cannot be " +
                        "found in request.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new InvalidRequestException("Invalid authorization request", OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_CLIENT);

        } else if (oAuthMessage.getSessionDataKeyFromLogin() != null && oAuthMessage.getResultFromLogin() == null) {

            if (log.isDebugEnabled()) {
                log.debug(
                        "Session data not found in SessionDataCache for " + oAuthMessage.getSessionDataKeyFromLogin());
            }
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null if diagnostic logs are disabled.
                diagnosticLogBuilder.resultMessage("Access denied since user session has timed-out.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new AccessDeniedException("Session Timed Out", OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ErrorCodes
                    .OAuth2SubErrorCodes.SESSION_TIME_OUT);

        } else if (oAuthMessage.getSessionDataKeyFromConsent() != null && oAuthMessage.getResultFromConsent() == null) {

            if (oAuthMessage.getResultFromLogin() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Session data not found in SessionDataCache for " + oAuthMessage
                            .getSessionDataKeyFromConsent());
                }
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Access denied since user session has timed-out.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new AccessDeniedException("Session Timed Out", OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ErrorCodes
                        .OAuth2SubErrorCodes.SESSION_TIME_OUT);
            } else {
                // if the sessionDataKeyFromConsent parameter present in the login request, skip it and allow login
                // since result from login is there.
                oAuthMessage.setSessionDataKeyFromConsent(null);
            }
        }
    }

    private void validateInputParameters(OAuthMessage oAuthMessage) throws InvalidRequestException {

        try {
            getOAuth2Service().validateInputParameters(oAuthMessage.getRequest());
        } catch (InvalidOAuthRequestException e) {
            throw new InvalidRequestException(e.getMessage(), e.getErrorCode(), e.getSubErrorCode());
        }
    }

    public void validateRepeatedParameters(OAuthMessage oAuthMessage) throws
            BadRequestException {

        if (!(oAuthMessage.getRequest() instanceof OAuthRequestWrapper)) {
            if (!EndpointUtil.validateParams(oAuthMessage, null)) {
                throw new BadRequestException("Invalid authorization request with repeated parameters",
                        OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_PARAMETERS);
            }
        }
    }
}
