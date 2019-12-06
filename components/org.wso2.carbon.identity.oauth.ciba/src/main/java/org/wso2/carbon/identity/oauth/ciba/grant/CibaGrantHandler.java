/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ciba.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.AUTH_REQ_ID;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.SEC_TO_MILLISEC_FACTOR;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.AUTHORIZATION_PENDING;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.EXPIRED_AUTH_REQ_ID;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.SLOW_DOWN;
import static org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes.INVALID_REQUEST;
import static org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes.OAuth2SubErrorCodes.CONSENT_DENIED;

/**
 * Grant Handler for CIBA.
 */
public class CibaGrantHandler extends AbstractAuthorizationGrantHandler {

    // Used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String MISSING_AUTH_REQ_ID = "auth_req_id_missing";
    private static final String INVALID_AUTH_REQ_ID = "invalid auth_req_id";
    private static final String INVALID_PARAMETERS = "invalid_request_parameters";

    private static Log log = LogFactory.getLog(CibaGrantHandler.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO responseDTO = super.issue(tokReqMsgCtx);
        String authReqId = getAuthReqId(tokReqMsgCtx);
        CibaAuthCodeDO cibaAuthCodeDO = retrieveCibaAuthCode(authReqId);

        try {
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                    .updateStatus(cibaAuthCodeDO.getCibaAuthCodeKey(), AuthReqStatus.TOKEN_ISSUED);
            if (log.isDebugEnabled()) {
                log.debug("Successfully updated the status of authentication request made by client:" +
                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            }
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception("Error occurred in persisting status for the request made with " +
                    "auth_req_id: " + authReqId, e);
        }
        return responseDTO;
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!super.validateGrant(tokReqMsgCtx)) {
            if (log.isDebugEnabled()) {
                log.debug("Successful in validating grant.Validation failed for the token request made by client: " +
                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            }
            return false;
        }

        // Obtain authentication request identifier from request.
        String authReqId = getAuthReqId(tokReqMsgCtx);

        try {
            // Check whether provided authReqId is a valid and retrieve AuthCode if exists.
            CibaAuthCodeDO cibaAuthCodeDO = retrieveCibaAuthCode(authReqId);

            // Check whether auth_req_id is not expired.
            validateAuthReqId(cibaAuthCodeDO);

            // Check whether token is issued for the authReqId.
            if (isTokenAlreadyIssued(cibaAuthCodeDO)) {
                throw new IdentityOAuth2Exception(INVALID_REQUEST);
            }

            // Validate whether authentication  is provided with affirmative consent.
            if (!isConsentGiven(cibaAuthCodeDO)) {
                throw new IdentityOAuth2Exception(CONSENT_DENIED);
            }

            // Validate whether polling is under proper rate limiting.
            validatePollingFrequency(cibaAuthCodeDO);

            // Validate whether user is authenticated.
            if (isAuthorizationPending(cibaAuthCodeDO)) {
                updateLastPolledTime(cibaAuthCodeDO);
                throw new IdentityOAuth2Exception(AUTHORIZATION_PENDING);
            }

            setPropertiesForTokenGeneration(tokReqMsgCtx, cibaAuthCodeDO);
            return true;
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception(INVALID_PARAMETERS, e);
        }
    }

    /**
     * Checks whether ciba authentication request identifier exists and .
     *
     * @param tokReqMsgCtx Authentication Request Identifier as JSON.
     * @return String Authentication Request Identifier from the request.
     * @throws IdentityOAuth2Exception Exception thrown regarding IdentityOAuth
     */
    private String getAuthReqId(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String authReqId = null; // Initiating auth_req_id.
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        // Obtaining auth_req_id from request.
        for (RequestParameter parameter : parameters) {
            if (AUTH_REQ_ID.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    authReqId = parameter.getValue()[0];
                }
            }
        }
        if (authReqId == null) {
            // Authentication Request ID is missing.

            if (log.isDebugEnabled()) {
                log.debug("token request misses mandated parameter (auth_req_id).");
            }
            throw new IdentityOAuth2Exception(MISSING_AUTH_REQ_ID);
        }
        return authReqId;
    }

    /**
     * Checks whether consent is provided or not.
     *
     * @param cibaAuthCodeDO Persisted DO which accumulates authentication and token request information.
     * @return Boolean Returns whether consent is provided or not.
     */
    private Boolean isConsentGiven(CibaAuthCodeDO cibaAuthCodeDO) {

        return !AuthReqStatus.CONSENT_DENIED.equals(cibaAuthCodeDO.getAuthReqStatus());
    }

    /**
     * Validates whether auth_req_id is still in active mode.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @throws IdentityOAuth2Exception,CibaCoreException
     */
    private void validateAuthReqId(CibaAuthCodeDO cibaAuthCodeDO) throws IdentityOAuth2Exception, CibaCoreException {

        // Check whether auth_req_id has expired or not.
        long expiresIn = cibaAuthCodeDO.getExpiresIn() * SEC_TO_MILLISEC_FACTOR;
        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long scheduledExpiryTime = cibaAuthCodeDO.getIssuedTime().getTime() + expiresIn;
        if (currentTimeInMillis > scheduledExpiryTime) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA auth_req_id is in expired state.Token Request Denied.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(cibaAuthCodeDO.getCibaAuthCodeKey(),
                    AuthReqStatus.EXPIRED);
            throw new IdentityOAuth2Exception(EXPIRED_AUTH_REQ_ID);
        }
    }

    /**
     * Validates the polling frequency of token request.
     *
     * @param cibaAuthCodeDO JSON auth_req_id from the tokenRequest.
     * @throws IdentityOAuth2Exception,CibaCoreException Identity Exception related to OAuth2.
     */
    private void validatePollingFrequency(CibaAuthCodeDO cibaAuthCodeDO)
            throws IdentityOAuth2Exception, CibaCoreException {

        // Check the frequency of polling and do the needful.
        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPollTimeInMillis = cibaAuthCodeDO.getLastPolledTime().getTime();
        long intervalInSec = cibaAuthCodeDO.getInterval();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeKey();
        if (currentTimeInMillis < lastPollTimeInMillis + intervalInSec * SEC_TO_MILLISEC_FACTOR) {
            long newInterval = intervalInSec + CibaConstants.INTERVAL_INCREMENT_VALUE_IN_SEC;
            if (log.isDebugEnabled()) {
                log.debug(" Rigorous polling for the token  made by client for request identified by " +
                        "cibaAuthCodeDOKey : " + cibaAuthCodeDO.getCibaAuthCodeKey() + ". Updated the Polling " +
                        "frequency on the table.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updatePollingInterval(cibaAuthCodeID, newInterval);
            throw new IdentityOAuth2Exception(SLOW_DOWN);
        }
    }

    /**
     * Updates the last polled time..
     *
     * @param cibaAuthCodeDO JSON auth_req_id from the tokenRequest.
     * @throws CibaCoreException CIBA core component exception.
     */
    private void updateLastPolledTime(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp latestPollingTime = new Timestamp(currentTimeInMillis);
        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateLastPollingTime(cibaAuthCodeDO.getCibaAuthCodeKey(),
                latestPollingTime);
    }

    /**
     * Validates whether user is authenticated or not.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @return Boolean Returns whether user is authenticated or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private boolean isAuthorizationPending(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        Enum authenticationStatus = cibaAuthCodeDO.getAuthReqStatus();
        String cibaAuthCodeKey = cibaAuthCodeDO.getCibaAuthCodeKey();
        if (!authenticationStatus.equals(AuthReqStatus.AUTHENTICATED)) {
            // If authenticated update the status as token delivered.
            return true;
        }
        if (log.isDebugEnabled()) {
            log.info("User still not authenticated for the request made by client for request uniquely identified" +
                    " by cibaAuthCodeKey : " + cibaAuthCodeKey);
        }
        return false;
    }

    /**
     * Validates whether token is issued already or not.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @return Boolean Returns whether token is already issued or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private boolean isTokenAlreadyIssued(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        Enum authenticationStatus = cibaAuthCodeDO.getAuthReqStatus();
        String cibaAuthCodeDOKey = cibaAuthCodeDO.getCibaAuthCodeKey();
        if (authenticationStatus.equals(AuthReqStatus.TOKEN_ISSUED)) {
            // Token is already delivered.
            return true;
        }
        if (log.isDebugEnabled()) {
            log.info("Token is not delivered for the request made for cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
        }
        return false;
    }

    /**
     * Sets the properties necessary for token generation.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @param tokReqMsgCtx   Token request Message Context.
     */
    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 CibaAuthCodeDO cibaAuthCodeDO) {

        tokReqMsgCtx
                .setAuthorizedUser(OAuth2Util.getUserFromUserName(cibaAuthCodeDO.getAuthenticatedUser().getUserName()));
        tokReqMsgCtx.setScope(cibaAuthCodeDO.getScopes());
    }

    /**
     * Validates whether provided auth_req_id exists in and return AuthCode if exists.
     *
     * @param authReqId Authentication Request Identifier.
     * @throws IdentityOAuth2Exception
     */
    private CibaAuthCodeDO retrieveCibaAuthCode(String authReqId) throws IdentityOAuth2Exception {

        try {
            String authCodeKey = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeKey(authReqId);

            if (StringUtils.isBlank(authCodeKey)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided auth_req_id : " +
                            authReqId + " with the token request is not valid.Or not issued by Identity server.");
                }
                throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
            }

            CibaAuthCodeDO cibaAuthCodeDO =
                    CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCode(authCodeKey);

            if (cibaAuthCodeDO.getAuthReqStatus().equals(AuthReqStatus.AUTHENTICATED)) {

                // Retrieve scopes.
                List<String> scope =
                        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getScopes(cibaAuthCodeDO.getCibaAuthCodeKey());
                cibaAuthCodeDO.setScopes(scope.toArray(new String[scope.size()]));

                // Retrieve authenticated user.
                AuthenticatedUser authenticatedUser = CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                        .getAuthenticatedUser(cibaAuthCodeDO.getCibaAuthCodeKey());
                cibaAuthCodeDO.setAuthenticatedUser(authenticatedUser);
            }
            return cibaAuthCodeDO;
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID, e);
        }
    }
}
