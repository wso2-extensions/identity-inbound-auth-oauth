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

package org.wso2.carbon.identity.oauth.ciba.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceDataHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Provides utilities for the functioning of other classes.
 */
public class CibaAuthUtil {

    private static final Log log = LogFactory.getLog(CibaAuthUtil.class);

    /**
     * Returns a unique AuthCodeDOKey.
     *
     * @return String Returns random uuid.
     */
    private static String getUniqueAuthCodeKey() {

        UUID id = UUID.randomUUID();
        return id.toString();
    }

    /**
     * Returns a unique auth_req_id.
     *
     * @return String Returns random uuid.
     */
    public static String getAuthReqID() {

        UUID id = UUID.randomUUID();
        return id.toString();
    }

    /**
     * Process and return the expires_in for auth_req_id.
     *
     * @param cibaAuthResponseDTO DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public static long getExpiresIn(CibaAuthResponseDTO cibaAuthResponseDTO) {

        long requestedExpiry = cibaAuthResponseDTO.getRequestedExpiry();
        if (requestedExpiry == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
        } else if (requestedExpiry < CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC) {
            return requestedExpiry;
        } else {
            log.warn("(requested_expiry) exceeds default maximum value for the CIBA authenticaton request made by : " +
                    cibaAuthResponseDTO.getIssuer());
            return CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC;
        }
    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static CibaAuthCodeDO generateCibaAuthCodeDO(CibaAuthResponseDTO cibaAuthResponseDTO)
            throws CibaCoreException {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPolledTimeInMillis = issuedTimeInMillis;
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);
        long expiryTime = cibaAuthResponseDTO.getRequestedExpiry();
        String[] scope = cibaAuthResponseDTO.getScope();
        cibaAuthCodeDO.setCibaAuthCodeKey(CibaAuthUtil.getUniqueAuthCodeKey());
        cibaAuthCodeDO.setAuthReqID(CibaAuthUtil.getAuthReqID());
        cibaAuthCodeDO.setConsumerAppKey(cibaAuthResponseDTO.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScope(scope);
        return cibaAuthCodeDO;
    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static AuthzRequestDTO buildAuthzRequestDO(CibaAuthResponseDTO cibaAuthResponseDTO,
                                                      CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        String clientID = cibaAuthResponseDTO.getIssuer();
        try {
            AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();
            String user = cibaAuthResponseDTO.getUserHint();
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
            String callbackUri = appDO.getCallbackUrl();
            authzRequestDTO.setNonce(cibaAuthCodeDO.getAuthReqID());
            authzRequestDTO.setCallBackUrl(callbackUri);
            authzRequestDTO.setUserHint(user);
            authzRequestDTO.setClientId(clientID);
            authzRequestDTO.setScopes(OAuth2Util.buildScopeString(cibaAuthResponseDTO.getScope()));

            if (StringUtils.isNotBlank(cibaAuthResponseDTO.getBindingMessage())) {
                authzRequestDTO.setBindingMessage(cibaAuthResponseDTO.getBindingMessage());
            }

            if (StringUtils.isNotBlank(cibaAuthResponseDTO.getTransactionContext())) {
                authzRequestDTO.setTransactionDetails(cibaAuthResponseDTO.getTransactionContext());
            }

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return authzRequestDTO;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException("Error in creating AuthorizeRequestDTO ", e);
        }
    }

    /**
     * Persist scopes.
     *
     * @param cibaAuthCodeDO DO with information regarding authenticationRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    private static void persistScopes(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().storeScope(cibaAuthCodeDO);
    }

    /**
     * Persist cibaAuthCode
     *
     * @param cibaAuthCodeDO DO with information regarding authenticationRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        CibaDAOFactory.getInstance().getCibaAuthMgtDAO().persistCibaAuthCode(cibaAuthCodeDO);
        persistScopes(cibaAuthCodeDO);
    }

    /**
     * Build and return ACR string as array.
     *
     * @param acrString ACR values as a String.
     * @return String Array.
     */
    public static String[] buildACRArray(String acrString) {

        if (StringUtils.isNotBlank(acrString)) {
            acrString = acrString.trim();
            return acrString.split("\\s");
        }
        return new String[0];
    }
}
