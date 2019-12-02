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
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
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
            throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO = generateCibaAuthCodeDO(cibaAuthCodeRequest);
        persistCibaAuthCode(cibaAuthCodeDO);
        return buildAuthCodeResponse(cibaAuthCodeRequest, cibaAuthCodeDO);
    }

    /**
     * Returns a unique AuthCodeDOKey.
     *
     * @return String Returns random uuid.
     */
    private static String generateAuthCodeKey() {

        return UUID.randomUUID().toString();
    }

    /**
     * Returns a unique auth_req_id.
     *
     * @return String Returns random uuid.
     */
    private static String generateAuthRequestId() {

        return UUID.randomUUID().toString();
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthCodeRequest DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    private static long getExpiresIn(CibaAuthCodeRequest cibaAuthCodeRequest) {

        long requestedExpiry = cibaAuthCodeRequest.getRequestedExpiry();
        if (requestedExpiry == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
        } else if (requestedExpiry < CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC) {
            return requestedExpiry;
        } else {
            log.warn("(requested_expiry) exceeds default maximum value for the CIBA authentication request made by : " +
                    cibaAuthCodeRequest.getIssuer());
            return CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC;
        }
    }

    /**
     * Builds and returns Ciba AuthCode DO.
     *
     * @param cibaAuthCodeRequest CIBA Request Data Transfer Object.
     * @return CibaAuthCodeDO.
     */
    private static CibaAuthCodeDO generateCibaAuthCodeDO(CibaAuthCodeRequest cibaAuthCodeRequest) {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        long expiryTime = getExpiresIn(cibaAuthCodeRequest);
        String[] scopes = cibaAuthCodeRequest.getScopes();
        cibaAuthCodeDO.setCibaAuthCodeKey(generateAuthCodeKey());
        cibaAuthCodeDO.setAuthReqID(generateAuthRequestId());
        cibaAuthCodeDO.setConsumerAppKey(cibaAuthCodeRequest.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(issuedTime); // Initially last polled time is set to issued time.
        cibaAuthCodeDO.setAuthenticationStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScope(scopes);
        return cibaAuthCodeDO;
    }

    /**
     * Builds and returns CibaAuthCodeResponse.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthCodeRequest Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private static CibaAuthCodeResponse buildAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest,
                                                              CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        String clientID = cibaAuthCodeRequest.getIssuer();
        try {
            CibaAuthCodeResponse cibaAuthCodeResponse = new CibaAuthCodeResponse();
            String user = cibaAuthCodeRequest.getUserHint();
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
            String callbackUri = appDO.getCallbackUrl();
            cibaAuthCodeResponse.setAuthReqId(cibaAuthCodeDO.getAuthReqID());
            cibaAuthCodeResponse.setCallBackUrl(callbackUri);
            cibaAuthCodeResponse.setUserHint(user);
            cibaAuthCodeResponse.setClientId(clientID);
            cibaAuthCodeResponse.setScopes(OAuth2Util.buildScopeString(cibaAuthCodeRequest.getScopes()));
            cibaAuthCodeResponse.setExpiresIn(cibaAuthCodeDO.getExpiresIn());

            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getBindingMessage())) {
                cibaAuthCodeResponse.setBindingMessage(cibaAuthCodeRequest.getBindingMessage());
            }

            if (StringUtils.isNotBlank(cibaAuthCodeRequest.getTransactionContext())) {
                cibaAuthCodeResponse.setTransactionDetails(cibaAuthCodeRequest.getTransactionContext());
            }

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return cibaAuthCodeResponse;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException("Error in creating AuthorizeRequestDTO ", e);
        }
    }

    /**
     * Persist cibaAuthCode.
     *
     * @param cibaAuthCodeDO DO with information regarding authenticationRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private static void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
    }
}
