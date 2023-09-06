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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAOImpl;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestCacheEntry;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Map;
import java.util.Optional;

/**
 * Caching layer for PAR Requests.
 */
public class CacheBackedParDAO implements ParMgtDAO {

    private static final Log log = LogFactory.getLog(CacheBackedParDAO.class);
    private final ParCache parCache = ParCache.getInstance();
    private final ParMgtDAOImpl parMgtDAO = new ParMgtDAOImpl();

    @Override
    public void persistRequestData(String requestURIReference, String clientId, long expiresIn,
                                   Map<String, String> parameters) throws ParCoreException {

        ParRequestCacheEntry parRequestCacheEntry = new ParRequestCacheEntry(requestURIReference, parameters,
                expiresIn, clientId);
        parMgtDAO.persistRequestData(requestURIReference, clientId, expiresIn, parameters);
        parCache.addToCache(requestURIReference, parRequestCacheEntry);
    }

    @Override
    public Optional<ParRequestDO> getRequestData(String requestURIReference) throws ParCoreException {

        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ParRequestCacheEntry parRequest = parCache.getValueFromCache(requestURIReference);
        Optional<ParRequestDO> parRequestDO;
        if (parRequest != null) {
            if (log.isDebugEnabled()) {
                log.debug(
                        String.format("Cache hit for expiry time of local uuid: %s for tenant: %s ",
                                requestURIReference, tenantDomain));
            }
            parRequestDO = Optional.of(new ParRequestDO(parRequest.getParams(), parRequest.getExpiresIn(),
                    parRequest.getClientId()));
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cache miss for expiry time of uuid:%s for tenant: %s ",
                        requestURIReference, tenantDomain));
            }
            parRequestDO = parMgtDAO.getRequestData(requestURIReference);
        }
        return parRequestDO;
    }

    @Override
    public void removeRequestData(String requestURIReference) throws ParCoreException {

        parCache.clearCacheEntry(requestURIReference);
        parMgtDAO.removeRequestData(requestURIReference);
    }
}
