/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.par.model;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.par.cache.CacheBackedParDAO;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;

import java.util.Calendar;
import java.util.HashMap;
import java.util.TimeZone;

/**
 * Data Handler for PAR.
 */
public class ParRetrieveHandler {

    private static final CacheBackedParDAO cacheBackedParDAO = new CacheBackedParDAO();

    public static HashMap<String, String> retrieveParamMap(String uuid, String oauthClientId)
            throws ParCoreException {

        HashMap<String, String> paramMap;


        if (StringUtils.isBlank(uuid)) {
            throw new ParCoreException(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI);
        }

        isRequestUriExpired(cacheBackedParDAO.getScheduledExpiry(uuid)); //checks if request expired
        isClientIdValid(oauthClientId, cacheBackedParDAO.getParClientId(uuid));

        paramMap = cacheBackedParDAO.getParParamMap(uuid);
        cacheBackedParDAO.removeParRequestData(uuid);

        return paramMap;
    }

    public static void isRequestUriExpired(long scheduledExpiryTime) throws ParCoreException {

        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis();

        if (currentTimeInMillis > scheduledExpiryTime) {
            throw new ParCoreException(OAuth2ErrorCodes.INVALID_REQUEST, "request_uri expired");
        }
    }

    public static void isClientIdValid(String oauthClientId, String parClientId) throws
            ParCoreException {

        if (!parClientId.equals(oauthClientId)) {
            throw new ParCoreException(OAuth2ErrorCodes.INVALID_CLIENT, "client_ids does not match");
        }
    }
}
