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

package org.wso2.carbon.identity.oauth.par.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAOImpl;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestCacheEntry;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Map;

/**
 * Caching layer for PAR Requests.
 */
public class CacheBackedParDAO implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(CacheBackedParDAO.class);
    private final ParCache parCache = ParCache.getInstance();
    private final ParMgtDAOImpl parMgtDAO = new ParMgtDAOImpl();

    @Override
    public void persistParRequest(String reqUriUUID, String clientId, long scheduledExpiryTime,
                                  Map<String, String> parameters) throws ParCoreException {

        ParRequestCacheEntry parRequestCacheEntry = new ParRequestCacheEntry(reqUriUUID, parameters,
                scheduledExpiryTime);
        parMgtDAO.persistParRequest(reqUriUUID, clientId, scheduledExpiryTime, parameters);
        parCache.addToCache(reqUriUUID, parRequestCacheEntry);
    }

    @Override
    public ParRequestDO getParRequest(String reqUriUUID) throws ParCoreException {

        ParRequestCacheEntry parCacheRequest = parCache.getValueFromCache(reqUriUUID);
        ParRequestDO parRequestDO;
        if (parCacheRequest != null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for expiry time of local uuid: %s for tenant:%s " + reqUriUUID);
            }
            return new ParRequestDO(parCacheRequest);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cache hit for expiry time of uuid:%s for tenant:%s " + reqUriUUID);
            }
            parRequestDO = parMgtDAO.getParRequest(reqUriUUID);
        }
        return parRequestDO;
    }

    @Override
    public void removeParRequest(String reqUriUUID) throws ParCoreException {

        parCache.clearCacheEntry(reqUriUUID);
        parMgtDAO.removeParRequest(reqUriUUID);
    }
}
