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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.api;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserNotificationHandler;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Provides authentication services.
 */
public class CibaAuthServiceImpl implements CibaAuthService {

    private static Log log = LogFactory.getLog(CibaAuthServiceImpl.class);

    @Override
    public CibaAuthCodeResponse generateAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest)
            throws CibaCoreException, CibaClientException {

        // Generate and persist the auth code
        CibaAuthCodeDO cibaAuthCodeDO = generateCibaAuthCodeDO(cibaAuthCodeRequest);
        
        // Resolve user and send notification.
        CibaUserResolver.ResolvedUser resolvedUser = resolveUser(cibaAuthCodeRequest);
        if (resolvedUser == null) {
            throw new CibaCoreException("Failed to resolve user for CIBA request from client: " +
                    cibaAuthCodeRequest.getIssuer());
        }
        cibaAuthCodeDO.setResolvedUserId(resolvedUser.getUserId());
        // Persist the auth code after resolving the user.
        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
        sendUserNotification(resolvedUser, cibaAuthCodeDO, cibaAuthCodeRequest.getBindingMessage());
        
        return buildAuthCodeResponse(cibaAuthCodeRequest, cibaAuthCodeDO);
    }

    /**
     * Resolves user from login_hint using the pluggable CibaUserResolver.
     *
     * @param cibaAuthCodeRequest The CIBA auth code request containing user hint
     * @return ResolvedUser if resolution is successful, null otherwise
     */
    private CibaUserResolver.ResolvedUser resolveUser(CibaAuthCodeRequest cibaAuthCodeRequest)
            throws CibaClientException, CibaCoreException {
        
        try {
            String clientId = cibaAuthCodeRequest.getIssuer();
            String userHint = cibaAuthCodeRequest.getUserHint();
            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(clientId);
            CibaUserResolver userResolver = CibaServiceComponentHolder.getInstance().getCibaUserResolver();
            if (userResolver == null) {
                throw new CibaCoreException("No CIBA User Resolver is configured to resolve user for CIBA request from " +
                        "client: " + clientId);
            }
            CibaUserResolver.ResolvedUser resolvedUser = userResolver.resolveUser(userHint, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("Successfully resolved user for CIBA request from client: " + clientId);
            }
            return resolvedUser;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException("Error resolving user for CIBA request: " + e.getMessage(), e);
        }
    }

    /**
     * Sends notification to the resolved user with authentication link.
     * This is a best-effort operation - failures are logged but don't fail the request.
     *
     * @param resolvedUser   The resolved user to send notification to
     * @param cibaAuthCodeDO The persisted auth code DO
     * @param bindingMessage Optional binding message to include in the notification
     */
    private void sendUserNotification(CibaUserResolver.ResolvedUser resolvedUser,
                                       CibaAuthCodeDO cibaAuthCodeDO,
                                       String bindingMessage) {
        
        try {
            CibaUserNotificationHandler notificationHandler = new CibaUserNotificationHandler();
            notificationHandler.sendNotification(resolvedUser, cibaAuthCodeDO, bindingMessage);
            
            if (log.isDebugEnabled()) {
                log.debug("User notification sent for CIBA auth_req_id: " + cibaAuthCodeDO.getAuthReqId());
            }
        } catch (CibaCoreException e) {
            log.error("Failed to send CIBA user notification: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error sending CIBA user notification: " + e.getMessage(), e);
        }
    }

    /**
     * Returns a unique AuthCodeKey.
     *
     * @return String Returns random uuid.
     */
    private String generateAuthCodeKey() {

        return UUID.randomUUID().toString();
    }

    /**
     * Returns a unique auth_req_id.
     *
     * @return String Returns random uuid.
     */
    private String generateAuthRequestId() {

        return UUID.randomUUID().toString();
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthCodeRequest Accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth_req_id.
     */
    private long getExpiresIn(CibaAuthCodeRequest cibaAuthCodeRequest) {

        long requestedExpiry = cibaAuthCodeRequest.getRequestedExpiry();
        if (requestedExpiry == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
        } else if (requestedExpiry < CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC) {
            return requestedExpiry;
        }
        if (log.isDebugEnabled()) {
            log.debug("The requested_expiry: " + requestedExpiry + " exceeds default maximum value: " +
                    CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC + " for the CIBA authentication request made " +
                    "by: " + cibaAuthCodeRequest.getIssuer());
        }
        return CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC;
    }

    /**
     * Builds and returns Ciba AuthCode DO.
     *
     * @param cibaAuthCodeRequest CIBA Request Data Transfer Object.
     * @return CibaAuthCodeDO.
     */
    private CibaAuthCodeDO generateCibaAuthCodeDO(CibaAuthCodeRequest cibaAuthCodeRequest) {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        long expiryTime = getExpiresIn(cibaAuthCodeRequest);
        String[] scopes = cibaAuthCodeRequest.getScopes();
        cibaAuthCodeDO.setCibaAuthCodeKey(this.generateAuthCodeKey());
        cibaAuthCodeDO.setAuthReqId(this.generateAuthRequestId());
        cibaAuthCodeDO.setConsumerKey(cibaAuthCodeRequest.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(issuedTime); // Initially last polled time is set to issued time.
        cibaAuthCodeDO.setAuthReqStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScopes(scopes);
        return cibaAuthCodeDO;
    }

    /**
     * Builds and returns CibaAuthCodeResponse.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthCodeRequest Auth Code request object.
     * @throws CibaCoreException   Exception thrown from CibaCore Component.
     * @throws CibaClientException Client exception thrown from CibaCore Component.
     */
    private CibaAuthCodeResponse buildAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest,
                                                       CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException, CibaClientException {

        String clientID = cibaAuthCodeRequest.getIssuer();
        try {
            CibaAuthCodeResponse cibaAuthCodeResponse = new CibaAuthCodeResponse();
            String user = cibaAuthCodeRequest.getUserHint();
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
            String callbackUri = appDO.getCallbackUrl();
            cibaAuthCodeResponse.setAuthReqId(cibaAuthCodeDO.getAuthReqId());
            cibaAuthCodeResponse.setCallBackUrl(callbackUri);
            cibaAuthCodeResponse.setUserHint(user);
            cibaAuthCodeResponse.setClientId(clientID);
            cibaAuthCodeResponse.setScopes(cibaAuthCodeRequest.getScopes());
            cibaAuthCodeResponse.setExpiresIn(cibaAuthCodeDO.getExpiresIn());

            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getBindingMessage())) {
                cibaAuthCodeResponse.setBindingMessage(cibaAuthCodeRequest.getBindingMessage());
            }
            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getTransactionContext())) {
                cibaAuthCodeResponse.setTransactionDetails(cibaAuthCodeRequest.getTransactionContext());
            }
            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthCodeResponse for the client: " + clientID);
            }
            return cibaAuthCodeResponse;
        } catch (IdentityOAuth2Exception e) {
            throw new CibaCoreException("Error in creating AuthCodeResponse for the client: " + clientID, e);
        } catch (InvalidOAuthClientException e) {
            throw new CibaClientException("Error in creating AuthCodeResponse for the client: " + clientID, e);
        }
    }
}
