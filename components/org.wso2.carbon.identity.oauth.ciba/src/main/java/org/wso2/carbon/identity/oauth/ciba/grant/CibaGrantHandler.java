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

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import javax.servlet.http.HttpServletResponse;

/**
 * Grant Handler for Ciba.
 */

public class CibaGrantHandler extends AbstractAuthorizationGrantHandler {

    // Used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    public static final String AUTH_REQ_ID = "auth_req_id";
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String MISSING_AUTH_REQ_ID = "auth_req_id_missing";
    private static final String SLOW_DOWN = "slow_down";
    private static final String AUTHORIZATION_PENDING = "authorization_pending";
    private static final String EXPIRED_TOKEN = "expired_token";
    private static final String CONSENT_DENIED = "consent_denied";
    private static final String INVALID_AUTH_REQ_ID = "invalid auth_req_id";
    private static final String INTERNAL_ERROR = "internal_error";
    private static final String INVALID_PARAMETERS = "invalid_request_parameters";

    private static Log log = LogFactory.getLog(CibaGrantHandler.class);

    /**
     * @param tokReqMsgCtx Token message request context.
     * @return Boolean Returns true if valid grant or else otherwise.
     * @throws IdentityOAuth2Exception OAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String auth_req_id = null; // Initiating auth_req_id.

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        // Obtaining auth_req_id from request.
        for (RequestParameter parameter : parameters) {
            if (AUTH_REQ_ID.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    auth_req_id = parameter.getValue()[0];
                }
            }
        }
        if (auth_req_id == null) {
            // Authentication Request ID is missing.

            if (log.isDebugEnabled()) {
                log.debug("token request  misses mandated parameter (auth_req_id).");
            }
            throw new IdentityOAuth2Exception(MISSING_AUTH_REQ_ID);
        }
        if (!tokenReq.getGrantType().equals(CibaParams.OAUTH_CIBA_GRANT_TYPE)) {
            // Grant Type is not expected to be for ciba.

            throw new IdentityOAuth2Exception(INVALID_GRANT);
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(auth_req_id);
            JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();
            String authCodeDOKey = this.getCibaAuthCodeDOKeyFromAuthReqCodeHash(auth_req_id);

            // Retrieving information from database and assign to CibaAuthCodeDO.
            CibaAuthCodeDO cibaAuthCodeDO =
                    CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeDO(authCodeDOKey);

            // Validate polling for tokenRequest.
            validatePolling(jo, auth_req_id, cibaAuthCodeDO);

            this.setPropertiesForTokenGeneration(tokReqMsgCtx, cibaAuthCodeDO);
            return true;
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception(INVALID_PARAMETERS);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
        }
    }

    /**
     * Validates the polling for tokenRequest.
     *
     * @param auth_req_id    Authentication Request Identifier as JSON.
     * @param authReqID      Authentication Request Identifier as String.
     * @param cibaAuthCodeDO Persisted DO which accumulates authentication and token request information.
     * @throws CibaCoreException       Exception thrown from CibaCore Component.
     * @throws IdentityOAuth2Exception Exception thrown regarding IdentityOAuth
     */
    private void validatePolling(JSONObject auth_req_id, String authReqID, CibaAuthCodeDO cibaAuthCodeDO)
            throws IdentityOAuth2Exception, CibaCoreException {

        try {
            // Validate whether provided authReqId is a valid.
            validateAuthReqID(authReqID);

            // Validate whether provided authReqId has a valid audience.
            validateAudience(auth_req_id);

            // Validate whether polling is allowed for the request made.
            validatePollingAllowed(cibaAuthCodeDO);

            // Validate whether provided authReqId is still active.
            activeAuthreqID(cibaAuthCodeDO);

            // Validate whether polling is under proper rate limiting.
            validatePollingFrequency(cibaAuthCodeDO);

            // Validate whether authentication  is provided with affirmative consent.
            if (IsConsentGiven(cibaAuthCodeDO).equals(false)) {
                throw new IdentityOAuth2Exception(CONSENT_DENIED);
            }

            // Validate whether user is authenticated.
            if (IsUserAuthenticated(cibaAuthCodeDO).equals(false)) {
                // Authentication status has to be obtained from db.

                throw new IdentityOAuth2Exception(AUTHORIZATION_PENDING);
            }
            if (log.isDebugEnabled()) {
                log.debug(
                        "Properly validated Token request with grantType : " + CibaParams.OAUTH_CIBA_GRANT_TYPE + " " +
                                "and auth_req_id : " + authReqID);
            }
        } catch (CibaCoreException ex) {
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, ex.getErrorDescription());
        }
    }

    /**
     * Checks whether consent is provided or not.
     *
     * @param cibaAuthCodeDO Persisted DO which accumulates authentication and token request information.
     * @return Boolean Returns whether consent is provided or not.
     */
    private Boolean IsConsentGiven(CibaAuthCodeDO cibaAuthCodeDO) {

        return !cibaAuthCodeDO.getAuthenticationStatus().equals(AuthenticationStatus.DENIED.toString());
    }

    /**
     * Returns CibaAuthCodeDOKey from provided auth_req_id.
     *
     * @param authReqID String auth_req_id from the tokenRequest.
     * @return String CibaAuthCodeDOKey.
     */
    private String getCibaAuthCodeDOKeyFromAuthReqCodeHash(String authReqID)
            throws CibaCoreException {

        try {
            String hashedCibaAuthReqCode = CibaAuthUtil.createHash(authReqID);
            if (CibaDAOFactory.getInstance().getCibaAuthMgtDAO().isHashedAuthReqIDExists(hashedCibaAuthReqCode)) {
                if (log.isDebugEnabled()) {
                    log.debug("Obtaining CibaAuthCodeDOKey for the hashedAuthReqId from the and auth_req_id : " +
                            authReqID);
                }
                return CibaDAOFactory.getInstance().getCibaAuthMgtDAO().getCibaAuthCodeDOKey(hashedCibaAuthReqCode);
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to obtain CibaAuthCodeDOKey for the hashedAuthReqId from the and auth_req_id : " +
                        authReqID);
            }
            throw new CibaCoreException(ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Validates provided auth_req_id.
     *
     * @param authReqID String auth_req_id from the tokenRequest.
     * @throws IdentityOAuth2Exception Identity Exception related to OAuth2.
     */
    private void validateAuthReqID(String authReqID)
            throws IdentityOAuth2Exception {
        // Validate whether auth_req_id issued or not.

        try {
            String hashedAuthReqID = CibaAuthUtil.createHash(authReqID);
            // Check whether the incoming auth_req_id exists/ valid.

            if (!CibaDAOFactory.getInstance().getCibaAuthMgtDAO().isHashedAuthReqIDExists(hashedAuthReqID)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided auth_req_id : " +
                            authReqID + "with the token request is not valid.Or not issued by Identity server.");
                }
                throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityOAuth2Exception(INTERNAL_ERROR);
        } catch (CibaCoreException e) {
            throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
        }
    }

    /**
     * Validates audience of auth_req_id.
     *
     * @param auth_req_id JSON auth_req_id from the tokenRequest.
     * @throws IdentityOAuth2Exception Identity Exception related to OAuth2.
     */
    private void validateAudience(JSONObject auth_req_id) throws IdentityOAuth2Exception {

        try {
            String audience = String.valueOf(auth_req_id.get("aud"));
            if (audience == null || StringUtils.isBlank(audience)) {
                //Audience does not not exist.

                throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
            }

            // Create app and check whether client app exists.
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(audience);
        } catch (InvalidOAuthClientException e) {

            // No such Audience registered for Identity server.
            throw new IdentityOAuth2Exception(INVALID_AUTH_REQ_ID);
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

        long expiryTime = cibaAuthCodeDO.getExpiryTime();
        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        if (currentTime > expiryTime) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA auth_req_id is in expired state.Token Request Denied.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistStatus(cibaAuthCodeDO.getCibaAuthCodeDOKey(),
                    AuthenticationStatus.EXPIRED.toString());
            throw new IdentityOAuth2Exception(EXPIRED_TOKEN);
        }
    }

    /**
     * Checks whether client is allowed to poll.
     *
     * @param cibaAuthCodeDO JSON auth_req_id from the tokenRequest.
     */
    private void validatePollingAllowed(CibaAuthCodeDO cibaAuthCodeDO) {

        // Incase of implementing 'ping mode' in future.
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

        long currentTime = ZonedDateTime.now().toInstant().toEpochMilli();
        long lastpolltime = cibaAuthCodeDO.getLastPolledTime();
        long interval = cibaAuthCodeDO.getInterval();
        String cibaAuthCodeID = cibaAuthCodeDO.getCibaAuthCodeDOKey();
        if (!(currentTime - lastpolltime > interval * 1000)) {
            long newInterval = interval + CibaParams.INTERVAL_INCREMENT;
            if (log.isDebugEnabled()) {
                log.debug(
                        "Incorrect Polling frequency for the request made by client for request uniquely identified " +
                                "by cibaAuthCodeDOKey : " + cibaAuthCodeDO.getCibaAuthCodeDOKey() +
                                ".Updated the Polling frequency on the table.");
            }
            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updatePollingInterval(cibaAuthCodeID, newInterval);
            throw new IdentityOAuth2Exception(SLOW_DOWN);
        }
        // Update last pollingTime.
        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().updateLastPollingTime(cibaAuthCodeID, currentTime);
    }

    /**
     * Validates whether user is authenticated or not.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @return Boolean Returns whether user is authenticated or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private Boolean IsUserAuthenticated(CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException {

        String authenticationStatus = cibaAuthCodeDO.getAuthenticationStatus();
        String cibaAuthCodeDOKey = cibaAuthCodeDO.getCibaAuthCodeDOKey();
        if (authenticationStatus.equals(AuthenticationStatus.AUTHENTICATED.toString())) {
            // If authenticated update the status as token delivered.

            CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistStatus(cibaAuthCodeDOKey, AuthenticationStatus.
                    TOKEN_DELIVERED.toString());
            return true;
        } else if (authenticationStatus.equals(AuthenticationStatus.TOKEN_DELIVERED.toString())) {
            // Token is already delivered.

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
     * Sets the properties necessary for token generation.
     *
     * @param cibaAuthCodeDO DO that accumulates information regarding authentication and token requests.
     * @param tokReqMsgCtx   Token request Message Context.
     */
    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 CibaAuthCodeDO cibaAuthCodeDO) {

        // Assigning the scopes.
        String[] scope = OAuth2Util.buildScopeArray(cibaAuthCodeDO.getScope());
        String authenticatedUserName = cibaAuthCodeDO.getAuthenticatedUser();
        tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(authenticatedUserName));
        tokReqMsgCtx.setScope(scope);
    }

}
