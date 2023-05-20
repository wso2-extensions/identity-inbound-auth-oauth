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

package org.wso2.carbon.identity.oauth.par.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAOImpl;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestCacheEntry;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Map;

/**
 *
 * Caching layer for PAR Requests.
 *
 */
public class CacheBackedParDAO implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(CacheBackedParDAO.class);
    private final ParCache parCache = ParCache.getInstance();
    private final ParMgtDAOImpl parMgtDAO = new ParMgtDAOImpl();

    @Override
    public void persistParRequest(String uuid, String clientId, long scheduledExpiryTime,
                                  Map<String, String> parameters) throws ParCoreException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

        ParRequestCacheEntry parRequestCacheEntry = new ParRequestCacheEntry(uuid, parameters, scheduledExpiryTime);
        parMgtDAO.persistParRequest(uuid, clientId, scheduledExpiryTime, parameters);
        parCache.addToCache(uuid, parRequestCacheEntry, tenantId);
    }

    @Override
    public ParRequestDO getParRequest(String uuid) throws ParCoreException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

        ParRequestCacheEntry parCacheRequest = parCache.getValueFromCache(uuid, tenantId);
        ParRequestDO parRequestDO;
        if (parCacheRequest != null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for expiry time of local uuid: %s for tenant:%s ",
                        uuid, tenantId));
            }
            return new ParRequestDO(parCache.getValueFromCache(uuid, tenantId));
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache hit for expiry time of uuid:%s for tenant:%s ",
                        uuid, tenantId));
            }
            parRequestDO = parMgtDAO.getParRequest(uuid);
        }
        return parRequestDO;
    }

    @Override
    public void removeParRequestData(String uuid) throws ParCoreException {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        parCache.clearCacheEntry(uuid, tenantId);
        parMgtDAO.removeParRequestData(uuid);
    }
}
