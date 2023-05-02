/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.model;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.CacheBackedParDAO;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;

import java.util.Calendar;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

/**
 * Data Handler for PAR.
 */
public class ParRetrieveHandler {

    private static Log log = LogFactory.getLog(ParRetrieveHandler.class);

    private static CacheBackedParDAO cacheBackedParDAO = new CacheBackedParDAO();
    private static int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

    public static HashMap<String, String> retrieveParamMap(String uuid, String oauthClientId)
            throws OAuthProblemException {

        HashMap<String, String> paramMap;
        String requestObject;

        try {
            if (StringUtils.isBlank(uuid)) {
                if (log.isDebugEnabled()) {
                    log.debug("Provided uuid : " +
                            uuid + " is not valid.Or not issued by Identity server.");
                }
                throw new ParClientException(OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI);
            }

            isRequestUriExpired(cacheBackedParDAO.fetchExpiryTime(uuid, tenantId)); //checks if request expired
            isClientIdValid(oauthClientId, cacheBackedParDAO.fetchClientId(uuid, tenantId));

            paramMap =  cacheBackedParDAO.fetchParamMap(uuid, tenantId);
            requestObject = cacheBackedParDAO.fetchRequestObj(uuid, tenantId);

            if (requestObject != null) {
                paramMap.put(OAuthConstants.OAuth20Params.REQUEST, requestObject);
            }

            return paramMap;
        } catch (ParClientException e) {
            throw new ParClientException(e.getError(), OAuth2ErrorCodes.OAuth2SubErrorCodes.INVALID_REQUEST_URI);
        }
    }

    public static void isRequestUriExpired(long requestTime) throws OAuthProblemException {

        long currentTime = Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis();
        long defaultExpiryInSecs = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;

        long duration = (currentTime - requestTime);

        if (!(TimeUnit.MILLISECONDS.toSeconds(duration) < defaultExpiryInSecs)) {
            throw new ParClientException("request_uri expired");
        }
    }

    public static void isClientIdValid(String oauthClientId, String parClientId) throws
            OAuthProblemException {

        if (!parClientId.equals(oauthClientId)) {
            throw new ParClientException("client_ids does not match");
        }
    }
}
