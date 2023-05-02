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

package org.wso2.carbon.identity.oauth.par.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;

import java.util.HashMap;

/**
 *
 * Caching wrapper for org.wso2.carbon.identity.claim.metadata.mgt.dao.ExternalClaimDAO.
 *
 */
public class CacheBackedParDAO {
    private static final Log log = LogFactory.getLog(CacheBackedParDAO.class);
    ParCache parCache = ParCache.getInstance();

    ParMgtDAO parMgtDAO = ParDAOFactory.getInstance().getParAuthMgtDAO();


    public void addParRequest(String uuid, ParRequest parRequest, int tenantId) {

        parCache.addToCache(uuid, parRequest, tenantId);
    }


    public HashMap<String, String> fetchParamMap (String uuid, int tenantId) throws OAuthProblemException {

        /**
         * What to have as key instead of request_uri?
         */
        //getting request from cache
        ParRequest parCacheRequest = parCache.getValueFromCache(uuid, tenantId);
        HashMap<String, String> paramMap;

        if (parCacheRequest == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for parameter map of local uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }

            //if request not in cache, fetch paramMap data from database
            paramMap = parMgtDAO.getParParamMap(uuid);
            System.out.println("ParamMap from DB: " + paramMap);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache hit for parameter map of uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }

            // get paramMap from cache
            paramMap = parCache.getValueFromCache(uuid, tenantId).getParameterMap();
            System.out.println("ParamMap from cache: " + paramMap);
        }
        return paramMap;
    }

    public long fetchExpiryTime (String uuid, int tenantId) throws OAuthProblemException {

        /**
         * What to have as key instead of request_uri?
         */
        ParRequest parCacheRequest = parCache.getValueFromCache(uuid, tenantId);
        long expiresIn;
        if (parCacheRequest == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for expiry time of local uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }

            // if request not in cache, fetch paramMap data from database
            expiresIn = parMgtDAO.getExpiresIn(uuid);
            System.out.println("Expiry from DB: " + expiresIn);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache hit for expiry time of uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }
            // get expiry from cache
            expiresIn = parCache.getValueFromCache(uuid, tenantId).getExpiresIn();
            System.out.println("Expiry from cache: " + expiresIn);
        }
        return expiresIn;
    }

    public String fetchClientId (String uuid, int tenantId) throws OAuthProblemException {

        /**
         * What to have as key instead of request_uri?
         */
        ParRequest parCacheRequest = parCache.getValueFromCache(uuid, tenantId);
        String parClientId;
        if (parCacheRequest == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for expiry time of local uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }

            // if request not in cache, fetch paramMap data from database
            parClientId = parMgtDAO.getParClientId(uuid);
            System.out.println("ClientID from DB: " + parClientId);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache hit for expiry time of uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }
            // get expiry from cache
            parClientId = parCache.getValueFromCache(uuid, tenantId).getClientId();
            System.out.println("ClientID from cache: " + parClientId);
        }
        return parClientId;
    }

    public String fetchRequestObj (String uuid, int tenantId) throws OAuthProblemException {

        /**
         * What to have as key instead of request_uri?
         */
        ParRequest parCacheRequest = parCache.getValueFromCache(uuid, tenantId);
        String requestObject;
        if (parCacheRequest == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for expiry time of local uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }

            // if request not in cache, fetch paramMap data from database
            requestObject = parMgtDAO.getRequestObject(uuid);
            System.out.println("ClientID from DB: " + requestObject);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache hit for expiry time of uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }
            // get expiry from cache
            requestObject = parCache.getValueFromCache(uuid, tenantId).getRequestObject();
            System.out.println("ClientID from cache: " + requestObject);
        }
        return requestObject;
    }
}
