/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.core;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthResponseData;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;


/**
 * Provides PAR services.
 */
public class ParAuthServiceImpl implements ParAuthService {

    ParMgtDAO parMgtDAO = ParDAOFactory.getInstance().getParAuthMgtDAO();

    @Override
    public ParAuthResponseData handleParAuthRequest(Map<String, String> parameters) throws ParCoreException {

        String uuid = UUID.randomUUID().toString();
        long expiry = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;

        ParAuthResponseData parAuthResponse = new ParAuthResponseData();
        parAuthResponse.setReqUriRef(uuid);
        parAuthResponse.setExpiryTime(expiry);

        persistParRequest(uuid, parameters, getScheduledExpiry(System.currentTimeMillis()));

        return parAuthResponse;
    }

    private void persistParRequest(String uuid, Map<String, String> params, long expiresIn)
            throws ParCoreException {

        parMgtDAO.persistRequestData(uuid, params.get(OAuthConstants.OAuth20Params.CLIENT_ID),
                expiresIn, params);
    }

    @Override
    public Map<String, String> retrieveParams(String uuid, String clientId) throws ParCoreException {

        ParRequestDO parRequestDO = parMgtDAO.getRequestData(uuid);
        parMgtDAO.removeRequestData(uuid);
        validateRequestURI(parRequestDO.getExpiresIn());
        validateClientID(clientId, parRequestDO.getClientId());

        return parRequestDO.getParams();
    }

    private void validateRequestURI(long expiresIn) throws ParCoreException {

        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis();

        if (currentTimeInMillis > expiresIn) {
            throw new ParCoreException(OAuth2ErrorCodes.INVALID_REQUEST, "request_uri expired");
        }
    }

    private void validateClientID(String clientId, String parClientId) throws
            ParCoreException {

        if (!StringUtils.equals(parClientId, clientId)) {
            throw new ParCoreException(OAuth2ErrorCodes.INVALID_CLIENT, "client_ids do not match.");
        }
    }

    private long getScheduledExpiry(long requestedTime) {

        long defaultExpiryInSecs = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC * ParConstants.SEC_TO_MILLISEC_FACTOR;
        return requestedTime + defaultExpiryInSecs;
    }
}
