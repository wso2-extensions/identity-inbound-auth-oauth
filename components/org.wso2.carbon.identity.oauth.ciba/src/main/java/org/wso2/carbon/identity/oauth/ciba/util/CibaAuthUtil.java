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
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
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
 * Provides utilities for the functioning of other classes.
 */
public class CibaAuthUtil {

    private static final Log log = LogFactory.getLog(CibaAuthUtil.class);

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
     * @param cibaAuthRequestDTO DTO accumulating validated parameters from CibaAuthenticationRequest.
     * @return long Returns expiry_time of the auth-req_id.
     */
    public static long getExpiresIn(CibaAuthRequestDTO cibaAuthRequestDTO) {

        long requestedExpiry = cibaAuthRequestDTO.getRequestedExpiry();
        if (requestedExpiry == 0) {
            return CibaConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;
        } else if (requestedExpiry < CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC) {
            return requestedExpiry;
        } else {
            log.warn("(requested_expiry) exceeds default maximum value for the CIBA authentication request made by : " +
                    cibaAuthRequestDTO.getIssuer());
            return CibaConstants.MAXIMUM_REQUESTED_EXPIRY_IN_SEC;
        }
    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthRequestDTO Status of the relevant Ciba Authentication.
     */
    public static CibaAuthCodeDO generateCibaAuthCodeDO(CibaAuthRequestDTO cibaAuthRequestDTO) {

        CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
        long issuedTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        long lastPolledTimeInMillis = issuedTimeInMillis;
        Timestamp issuedTime = new Timestamp(issuedTimeInMillis);
        Timestamp lastPolledTime = new Timestamp(lastPolledTimeInMillis);
        long expiryTime = CibaAuthUtil.getExpiresIn(cibaAuthRequestDTO);
        String[] scope = cibaAuthRequestDTO.getScope();
        cibaAuthCodeDO.setCibaAuthCodeKey(CibaAuthUtil.generateAuthCodeKey());
        cibaAuthCodeDO.setAuthReqID(CibaAuthUtil.generateAuthRequestId());
        cibaAuthCodeDO.setConsumerAppKey(cibaAuthRequestDTO.getIssuer());
        cibaAuthCodeDO.setIssuedTime(issuedTime);
        cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
        cibaAuthCodeDO.setAuthenticationStatus(AuthReqStatus.REQUESTED);
        cibaAuthCodeDO.setInterval(CibaConstants.INTERVAL_DEFAULT_VALUE_IN_SEC);
        cibaAuthCodeDO.setExpiresIn(expiryTime);
        cibaAuthCodeDO.setScope(scope);
        return cibaAuthCodeDO;
    }

    /**
     * Builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthRequestDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public static CibaAuthResponseDTO buildAuthResponseDTO(CibaAuthRequestDTO cibaAuthRequestDTO,
                                                           CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        String clientID = cibaAuthRequestDTO.getIssuer();
        try {
            CibaAuthResponseDTO cibaAuthResponseDTO = new CibaAuthResponseDTO();
            String user = cibaAuthRequestDTO.getUserHint();
            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
            String callbackUri = appDO.getCallbackUrl();
            cibaAuthResponseDTO.setAuthReqId(cibaAuthCodeDO.getAuthReqID());
            cibaAuthResponseDTO.setCallBackUrl(callbackUri);
            cibaAuthResponseDTO.setUserHint(user);
            cibaAuthResponseDTO.setClientId(clientID);
            cibaAuthResponseDTO.setScopes(OAuth2Util.buildScopeString(cibaAuthRequestDTO.getScope()));
            cibaAuthResponseDTO.setExpiresIn(cibaAuthCodeDO.getExpiresIn());

            if (StringUtils.isNotBlank(cibaAuthRequestDTO.getBindingMessage())) {
                cibaAuthResponseDTO.setBindingMessage(cibaAuthRequestDTO.getBindingMessage());
            }

            if (StringUtils.isNotBlank(cibaAuthRequestDTO.getTransactionContext())) {
                cibaAuthResponseDTO.setTransactionDetails(cibaAuthRequestDTO.getTransactionContext());
            }

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return cibaAuthResponseDTO;
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
     * Persist cibaAuthCode.
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
