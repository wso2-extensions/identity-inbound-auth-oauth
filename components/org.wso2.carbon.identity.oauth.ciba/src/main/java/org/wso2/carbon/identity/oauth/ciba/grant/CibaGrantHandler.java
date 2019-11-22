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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
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
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.AUTH_REQ_ID;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.SEC_TO_MILLISEC_FACTOR;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.AUTHORIZATION_PENDING;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.EXPIRED_TOKEN;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.INVALID_REQUEST;
import static org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes.SLOW_DOWN;
import static org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes.OAuth2SubErrorCodes.CONSENT_DENIED;

/**
 * Grant Handler for CIBA.
 */

public class CibaGrantHandler extends AbstractAuthorizationGrantHandler {

    // Used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String MISSING_AUTH_REQ_ID = "auth_req_id_missing";

    private static final String INVALID_AUTH_REQ_ID = "invalid auth_req_id";
    private static final String INTERNAL_ERROR = "internal_error";
    private static final String INVALID_PARAMETERS = "invalid_request_parameters";
    private static String CIBA_AUTH_CODE_KEY;

    private static Log log = LogFactory.getLog(CibaGrantHandler.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO responseDTO = super.issue(tokReqMsgCtx);

        try {
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(CIBA_AUTH_CODE_KEY, AuthenticationStatus.
                    TOKEN_ISSUED);
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception("Error occured in persisting status.", e);
        }
        return responseDTO;
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }

        // Obtain authentication request identifier from request.
        String authReqId = getAuthReqId(tokReqMsgCtx);

        try {
            // Check whether provided authReqId is a valid.
            validateAuthReqID(authReqId);

            // Retrieving information from database and assign to CibaAuthCodeDO.
            CibaAuthCodeDO cibaAuthCodeDO = retrieveCibaAuthCodeDO(authReqId);

            // Assign key.
            CIBA_AUTH_CODE_KEY = cibaAuthCodeDO.getCibaAuthCodeKey();

            // Check whether auth_req_id is not expired.
            activeAuthreqID(cibaAuthCodeDO);

            // Check whether token is issued for the authReqId.
            if (isTokenAlreadyIssued(cibaAuthCodeDO)) {
                throw new IdentityOAuth2Exception(INVALID_REQUEST);
            }

            // Validate whether user is authenticated.
            if (isAuthorizationPending(cibaAuthCodeDO)) {
                throw new IdentityOAuth2Exception(AUTHORIZATION_PENDING);
            }

            // Validate whether authentication  is provided with affirmative consent.
            if (!isConsentGiven(cibaAuthCodeDO)) {
                throw new IdentityOAuth2Exception(CONSENT_DENIED);
            }

            // Validate whether polling is under proper rate limiting.
            validatePollingFrequency(cibaAuthCodeDO);

            this.setPropertiesForTokenGeneration(tokReqMsgCtx, cibaAuthCodeDO);
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

        return !cibaAuthCodeDO.getAuthenticationStatus().equals(AuthenticationStatus.DENIED);
    }

    /**
     * Validates provided auth_req_id.
     *
     * @param authReqID String auth_req_id from the tokenRequest.
     * @throws IdentityOAuth2Exception Identity Exception related to OAuth2.
     */
    private void validateAuthReqID(String authReqID) throws IdentityOAuth2Exception {
        // Validate whether provided auth_req_id is valid or not.

        try {
            if (!CibaDAOFactory.getInstance().getCibaAuthMgtDAO().isAuthReqIDExist(authReqID)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided auth_req_id : " +
                            authReqID + "with the token request is not valid.Or not issued by Identity server.");
                }
                throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
            }
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID, e);
        }
    }

    /**
     * Validates whether auth_req_id is still in active mode.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @throws IdentityOAuth2Exception,CibaCoreException
     */
    private void activeAuthreqID(CibaAuthCodeDO cibaAuthCodeDO) throws IdentityOAuth2Exception, CibaCoreException {
        // Check whether auth_req_id has expired or not.

        long expiresIn = cibaAuthCodeDO.getExpiresIn() * SEC_TO_MILLISEC_FACTOR;
        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long scheduledExpiryTime = cibaAuthCodeDO.getIssuedTime().getTime() + expiresIn;

        log.info("Expires in ms" + expiresIn);
        log.info("current UTC time ms " + currentTimeInMillis);
        log.info("scheuled expiry : " + scheduledExpiryTime);
        if (currentTimeInMillis > scheduledExpiryTime) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA auth_req_id is in expired state.Token Request Denied.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateStatus(cibaAuthCodeDO.getCibaAuthCodeKey(),
                    AuthenticationStatus.EXPIRED);
            throw new IdentityOAuth2Exception(EXPIRED_TOKEN);
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
        long lastPolltimeInMillis = cibaAuthCodeDO.getLastPolledTime().getTime();
        long intervalInSec = cibaAuthCodeDO.getInterval();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeKey();
        if ((currentTimeInMillis < lastPolltimeInMillis + intervalInSec * SEC_TO_MILLISEC_FACTOR)) {
            long newInterval = intervalInSec + CibaConstants.INTERVAL_INCREMENT_VALUE_IN_SEC;
            if (log.isDebugEnabled()) {
                log.debug(
                        "Incorrect Polling frequency for the request made by client for request uniquely identified " +
                                "by cibaAuthCodeDOKey : " + cibaAuthCodeDO.getCibaAuthCodeKey() +
                                ".Updated the Polling frequency on the table.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updatePollingInterval(cibaAuthCodeID, newInterval);
            throw new IdentityOAuth2Exception(SLOW_DOWN);
        }
        // Update last pollingTime.
        Timestamp latestPollingTime = new Timestamp(currentTimeInMillis);
        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateLastPollingTime(cibaAuthCodeID,
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

        Enum authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
        String cibaAuthCodeDOKey = cibaAuthCodeDO.getCibaAuthCodeKey();
        if (authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED)) {
            // If authenticated update the status as token delivered.
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.info("User still not authenticated for the request made by client for request uniquely identified" +
                        " by cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            return false;
        }
    }

    /**
     * Validates whether token is issued already or not.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @return Boolean Returns whether token is already issued or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private boolean isTokenAlreadyIssued(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        Enum authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
        String cibaAuthCodeDOKey = cibaAuthCodeDO.getCibaAuthCodeKey();
        if (authenticationStatus.equals(AuthenticationStatus.TOKEN_ISSUED)) {
            // Token is already delivered.
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.info("Token is not delivered for the request made for cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            return false;
        }
    }

    /**
     * Sets the properties necessary for token generation.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @param tokReqMsgCtx   Token request Message Context.
     */
    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 CibaAuthCodeDO cibaAuthCodeDO) {

        tokReqMsgCtx.setAuthorizedUser(
                OAuth2Util.getUserFromUserName(cibaAuthCodeDO.getAuthenticatedUser().getUserName()));
        tokReqMsgCtx.setScope(cibaAuthCodeDO.getScope());
    }

    private CibaAuthCodeDO retrieveCibaAuthCodeDO(String authReqId) throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO =
                CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeWithAuhReqID(authReqId);

        // Retrieve scopes.
        String[] scope = CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getScope(cibaAuthCodeDO);
        cibaAuthCodeDO.setScope(scope);

        // Retrieve authenticated user.
        AuthenticatedUser authenticatedUser = CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                .getAuthenticatedUser(cibaAuthCodeDO.getCibaAuthCodeKey());
        cibaAuthCodeDO.setAuthenticatedUser(authenticatedUser);

        return cibaAuthCodeDO;

    }
}
