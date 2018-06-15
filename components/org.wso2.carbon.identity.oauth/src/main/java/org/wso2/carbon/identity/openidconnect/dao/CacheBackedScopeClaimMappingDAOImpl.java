/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCache;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCacheEntry;
import org.wso2.carbon.identity.openidconnect.model.Scope;

import java.util.List;

/**
 * Default cache backed implementation of {@link DefaultScopeClaimMappingDAO}. This handles {@link OIDCScopeClaimCache}
 * related cache layer operations.
 */
public class CacheBackedScopeClaimMappingDAOImpl extends DefaultScopeClaimMappingDAOImpl {

    private final Log log = LogFactory.getLog(CacheBackedScopeClaimMappingDAOImpl.class);
    private OIDCScopeClaimCache oidcScopeClaimCache = OIDCScopeClaimCache.getInstance();
    private DefaultScopeClaimMappingDAO defaultScopeClaimMappingDAO = new DefaultScopeClaimMappingDAOImpl();

    @Override
    public void insertAllScopesAndClaims(int tenantId, List<Scope> scopes) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
        oidcScopeClaimCacheEntry.setList(scopes);
        super.insertAllScopesAndClaims(tenantId, scopes);
        oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
        if (log.isDebugEnabled()) {
            log.debug("OIDC scopes and mapped claims are inserted to the database and to the cache for the tenant : "
                    + tenantId);
        }
    }

    @Override
    public List<Scope> loadScopesClaimsMapping(int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        if (oidcScopeClaimCacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setList(defaultScopeClaimMappingDAO.loadScopesClaimsMapping(tenantId));
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        return oidcScopeClaimCacheEntry.getList();
    }

    @Override
    public void deleteScopeAndClaims(String scope, int tenantId) throws IdentityOAuthAdminException {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        if (log.isDebugEnabled()) {
            log.debug("OIDC scope claims mapping deleted from the oidcScopeClaimCache for tenant: " + tenantId);
        }
    }

    @Override
    public void addNewClaimsForScope(String scope, List<String> claims, int tenantId) throws IdentityOAuth2Exception {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        if (log.isDebugEnabled()) {
            log.debug("OIDC scope claims mapping deleted from the oidcScopeClaimCache for tenant: " + tenantId);
        }
    }

    @Override
    public int loadSingleScopeRecord(int tenantId) throws IdentityOAuth2Exception {

        int id = 1;
        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        if (oidcScopeClaimCacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            //if the cache does not contain oidc scope claim mapping details, load data from the db.
            id = defaultScopeClaimMappingDAO.loadSingleScopeRecord(tenantId);
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setList(loadScopesClaimsMapping(tenantId));
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scope claim mappings are loaded to the cache layer for tenant: " + tenantId);
            }

        }
        return id;
    }
}
